//------------------------------------------------------------------------------
// plugin_print_funcnames Clang sample. Demonstrates:
//
// * How to create a Clang plugin.
// * How to use AST actions to access the AST of the parsed code.
//
// Once the .so is built, it can be loaded by Clang. For example:
//
// $ clang -cc1 -load build/plugin_print_funcnames.so -plugin print-fns <cfile>
//
// Taken from the Clang distribution. LLVM's license applies.
//------------------------------------------------------------------------------

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include <sstream>
#include <iterator>
#include <string>
#include <vector>
#include <iostream>

#include <jsoncpp/json/json.h>

using namespace clang;

#define DEBUG_FUNCTION ""

#include "utils.hpp"

struct GlobalState{
    // XXX: not entirely sure this is still needed after the VarID introduction..
    std::set<MemberExpr *> AlreadyProcessedMEs;
    std::set<Stmt *> AlreadyProcessedCSs;
    std::pair<VarDecl *, Expr *> DeferredVarInit;
    
    // The following globals keep track of how a VarDecl is initialized.
    // VarInitFromME is list because a variable can overwrite itself
    // multiple times (vm_start = vm_start->vm_next; vm_start =
    // vm_start->vm_end);
    
    std::map<VarDecl*, std::list<MemberExpr*>> VarInitFromME;
    std::map<VarDecl*, Decl*> VarInitFromD;
    std::map<VarDecl*, OffsetOfExpr*> VarInitContainerOf;    
    std::map<MemberExpr*, Decl*> MEInitFromDecl;
    std::map<MemberExpr*, MemberExpr*> MEInitFromME;

    // This map associated a VarDecl with an ID
    std::map<VarDecl*, int> VarID;
    int GlobalID = 0;
};


struct VarInit {
    OffsetOfExpr *OE;
    FunctionDecl *FD;
    MemberExpr *ME;
    VarDecl *VD;
    Decl *D;
};

typedef struct VarInit VarInit;

class FindNamedClassVisitor
    : public RecursiveASTVisitor<FindNamedClassVisitor> {
public:
    explicit FindNamedClassVisitor(ASTContext *Context)
        : Context(Context) {}


    // Check this because it might be not updated.
    GlobalState *CopyGlobalState(GlobalState *GS){
        GlobalState *GS2 = new GlobalState;

        GS2->AlreadyProcessedMEs = GS->AlreadyProcessedMEs;
        GS2->DeferredVarInit = GS->DeferredVarInit;
        GS2->VarInitFromME = GS->VarInitFromME;
        GS2->VarInitFromD = GS->VarInitFromD;
        GS2->VarInitContainerOf = GS->VarInitContainerOf;
        GS2->MEInitFromDecl = GS->MEInitFromDecl;
        GS2->MEInitFromME = GS->MEInitFromME;
        GS2->VarID = GS->VarID;
        GS2->GlobalID = GS->GlobalID;
        
        return GS2;
    }

    int id(){
        GS->GlobalID++;
        return GS->GlobalID;
    }

    std::string getQTypeStr(QualType QT){
        return getTypeStr(QT.getTypePtr());
    }

    std::string getTypeStr(const Type *T){
        QualType QT = getQualType(T);
        // Here we also check that we are dealing with a pointer, we want to avoid structs passed by value..
        if(QT.isNull() || T->isVoidType() || T->isVoidPointerType()){
            return "";
        }
        QT = QT.getDesugaredType(*Context);
        return QT.getUnqualifiedType().getAsString();
    }

    std::string getTypeFromExpr(Expr *E){
        const Type *T = E->getType().getTypePtr();
        // Here we handle anonymous structure (es: tk_core)
        if (T->hasUnnamedOrLocalType()){
            if(DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(E)){
                if(VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl()))
                   return "struct ANON_" + GetVarName(VD);
            }
        }

        return getTypeStr(T);
    }

    std::string GetFunctionInfo(FunctionDecl *FD){
        return GetDeclFilename(FD) + "|" + GetFunctionName(FD);        
    }
    
    std::string GetDeclFilename(Decl *FD){
        FullSourceLoc FullLocation = Context->getFullLoc(FD->getBeginLoc());
        if (not FullLocation.isValid())
            return "";
        if (FullLocation.getFileEntry())
            return FullLocation.getFileEntry()->getName().str();
        else
            return FullLocation.getExpansionLoc().getFileEntry()->getName().str();
    }

    std::string GetStmtBegin(Stmt *S){
        FullSourceLoc FullLocation = Context->getFullLoc(S->getBeginLoc());
        if(not FullLocation.isValid())
            return "";
        return std::to_string(FullLocation.getExpansionLineNumber());
    }

    std::string GetDeclBegin(Decl *FD){
        FullSourceLoc FullLocation = Context->getFullLoc(FD->getBeginLoc());
        if(not FullLocation.isValid())
            return "";
        return std::to_string(FullLocation.getExpansionLineNumber());
    }

    std::string GetDeclEnd(Decl *FD){
        FullSourceLoc FullLocation = Context->getFullLoc(FD->getEndLoc());
        if(not FullLocation.isValid())
            return "";
        return std::to_string(FullLocation.getExpansionLineNumber());
    }

    bool isZero(Expr *E){
        bool result;
        bool evaluates = E->EvaluateAsBooleanCondition(result, *Context);
        return (evaluates and result == 0);
    }
    
    bool isIfZero(IfStmt * IS){
        if(BinaryOperator *BO = dyn_cast<BinaryOperator>(IS->getCond()))
            if(BO->getOpcodeStr() == "&")
                return isZero(BO->getLHS()) || isZero(BO->getRHS());

        return isZero(IS->getCond());
    }

    bool isFieldNamed(FieldDecl *FD){
        return FD->getNameAsString() != "";
    }

    std::string isFieldPointer(FieldDecl *FD){
        return std::to_string(FD->getType()->isPointerType());
    }

    // It returns the size of RD, comprehensive of the sizes of nested anonymous structs/unions.
    int getRDLength(RecordDecl *RD){
        int Size = 0;
        for (auto *D: RD->decls()){
            if(isa<FieldDecl>(D) && dyn_cast<FieldDecl>(D)->getNameAsString() != "")
                Size+=1;
        
            if(RecordDecl *RDD = dyn_cast<RecordDecl>(D))
                if(RDD->isAnonymousStructOrUnion())
                    Size += getRDLength(RDD) + 1;
        }
    
        return Size;
    }
        std::string getFieldTypeStr(FieldDecl *FD){
        const Type *T = FD->getType().getTypePtr();
        QualType QT = FD->getType();;
        if(T->isPointerType()){
            QT = T->getPointeeType();
        }
        
        QT = QT.getDesugaredType(*Context);
        return QT.getUnqualifiedType().getAsString();
    }
    
    void RecursiveVisitRecordDecl(RecordDecl *RD, Json::Value &Root){
        std::string Name;
        
        Json::Value Field;
        for (auto *D: RD->decls()){
            Field.clear();
            if(FieldDecl *FD = dyn_cast<FieldDecl>(D)){
                if(isFieldNamed(FD)){
                    Field = MapToJson({
                            {"name", FD->getNameAsString()},
                            {"line", GetDeclBegin(FD)},
                            {"is_pointer", isFieldPointer(FD)},
                            {"field_type", getFieldTypeStr(FD)}
                        });
                    
                    Root["body"].append(Field);
                }
            }
        
            if(RecordDecl *RDD = dyn_cast<RecordDecl>(D)){
                if(RDD->isAnonymousStructOrUnion()){
                    Name = RDD->getTypeForDecl()->isUnionType() ? "anon_union" : "anon_struct";
                    Field = MapToJson({
                            {"name", Name},
                            {"line", std::to_string(getRDLength(RDD))},
                            {"is_pointer", "0"}
                        });
                    
                    Root["body"].append(Field);                    
                    RecursiveVisitRecordDecl(RDD, Root);
                }
            }
        }
    }

    Json::Value MapToJson(std::map<std::string, std::string> m){
        Json::Value V;
        for (auto&& element: m) {
            V[element.first] = element.second;
        }
        return V;
    }

    Json::Value ListToJson(std::list<std::string> l){
        Json::Value V;
        for (auto&& element: l) {
            V.append(element);
        }
        return V;
    }
    
    void Log(Json::Value Root){
        Json::FastWriter fast;        
        std::string sFast = "\n" + fast.write(Root);
        llvm::errs() << sFast;
    }

    void LogStyled(Json::Value Root){
        Json::StyledWriter fast;
        std::string sFast = fast.write(Root);
        llvm::errs() << sFast;
    }

    bool VisitRecordDecl(RecordDecl *RD, std::string struct_type = ""){
        if (DEBUG_FUNCTION != "")
            return true;

        Json::Value Root;
        if(RD->field_empty() || (RD->getTypeForDecl()->hasUnnamedOrLocalType() and struct_type == ""))
            return true;


        Root["type"] = "RECORD";
        Root["filename"] = GetDeclFilename(RD);
        Root["start"] = GetDeclBegin(RD);
        Root["end"] = GetDeclEnd(RD);
        
        if (struct_type == "")
            Root["struct_type"] = getTypeFromRecordDecl(RD);
        else
            Root["struct_type"] = struct_type;
        
        RecursiveVisitRecordDecl(RD, Root);
        Log(Root);
        
        return true;
    }

    
    // In case there is a chain of anonymous struct, then we skip it all of them.
    // `-MemberExpr 0x58b03b8 'u32':'unsigned int' lvalue .len 0x521cdc8
    //  `-MemberExpr 0x58b0380 'struct qstr::(anonymous at ./include/linux/dcache.h:49:3)' lvalue . 0x521ce68
    //   `-MemberExpr 0x58b0330  'union qstr::(anonymous at ./include/linux/dcache.h:48:2)' lvalue . 0x521d058
    //   `-MemberExpr 'struct qstr':'struct qstr' lvalue ->d_name 0x521db38 <-------

    // MemberExpr 0x67ca9c8 'const u32':'const unsigned int' lvalue .len 0x5de64f8
    // `-MemberExpr 0x67ca990 'const struct qstr::(anonymous at ./include/linux/dcache.h:49:3)' lvalue . 0x5de6598
    // `-MemberExpr 0x67ca940 'const union qstr::(anonymous at ./include/linux/dcache.h:48:2)' lvalue -> 0x5de6788 <----
    // `-ImplicitCastExpr 0x67ca928 'const struct qstr *' <LValueToRValue>
    // `-DeclRefExpr 0x67ca900 'const struct qstr *' lvalue ParmVar 0x67ca548 'qstr' 'const struct qstr *'

    MemberExpr* SkipAnon(MemberExpr *ME){
        if(!isa<MemberExpr>(ME->getBase()))
            return ME;
        
        GS->AlreadyProcessedMEs.insert(ME);
        if (isAnonStructOrUnion(ME) and isa<MemberExpr>(ME->getBase())){            
            return SkipAnon(dyn_cast<MemberExpr>(ME->getBase()));
        }        
        return ME;
    }

    void AppendContainerOf(OffsetOfExpr *OE, std::list<std::string>* result, bool front){
        FieldDecl *FD;
        std::string StructType, FieldName, tmp;

        bool isArray = false;
        // list_entry(first, struct task_struct, pids[(type)].node);
        if(OE->getNumComponents() == 3 and OE->getComponent(1).getKind() == clang::OffsetOfNode::Kind::Array){
            isArray = true;
        }
        
        // container_of(.., struct sock, sk_node);
        if(OE->getNumComponents() == 3){
            if (not isArray){
                StructType = getTypeFromRecordDecl(OE->getComponent(1).getField()->getParent());
                FieldName = OE->getComponent(2).getField()->getNameAsString();
            }
            else{
                StructType = getTypeFromRecordDecl(OE->getComponent(2).getField()->getParent());
                FieldName = OE->getComponent(2).getField()->getNameAsString();
            }                
            
            tmp = StructType + "." + FieldName;
            if (front)
                result->push_front(tmp);
            else
                result->push_back(tmp);            
        }
        
        FD = OE->getComponent(0).getField();
        StructType = getTypeFromRecordDecl(FD->getParent());
        FieldName = FD->getNameAsString();
        tmp = "CONTAINER_OF " + StructType + "->" + FieldName;
        if (isArray)
            tmp = "ARRAY " + tmp;
        
        if (front)
            result->push_front(tmp);
        else
            result->push_back(tmp);

    }

    bool isParentAmpersand(MemberExpr *ME){
        Stmt *S = PM->getParent(ME);
        if(UnaryOperator *UO = dyn_cast<UnaryOperator>(S))
            if (UnaryOperator::getOpcodeStr(UO->getOpcode()) == "&")
                return true;
        return false;
    }

    bool isArray(Stmt *Child){
        Stmt *Parent = PM->getParent(Child);
        ArraySubscriptExpr *ASE = dyn_cast_or_null<ArraySubscriptExpr>(Parent);
        if(!ASE)
            return false;

        if (ASE->getBase() == Child)
            return true;
        return false;
    }
    
    bool isParentArray(MemberExpr *ME){
        Stmt *S = PM->getParent(ME);
        if (isArray(ME) or isArray(S))
            return true;
        return false;
    }

    // Returns a textual representation of the MemberExpr: "struct task_struct->mm"
    std::string ExtractStructAndField(MemberExpr *ME){
        std::string Separator = ME->isArrow() ? "->" : ".";
        std::string Ampersand = isParentAmpersand(ME) ? "&" : "";
        std::string Array = isParentArray(ME) ? "ARRAY " : "";
        
        ME = SkipAnon(ME);
        
        std::string FieldName = dyn_cast<FieldDecl>(ME->getMemberDecl())->getNameAsString();
        llvm::errs() << "Field: " << FieldName << "\n";
        Expr *base = ME->getBase();
        
        if (isa<MemberExpr>(base)){
            ME = SkipAnon(dyn_cast<MemberExpr>(base));
            if(isAnonStructOrUnion(ME)){ // See the two examples on for SkipAnon.
                Separator = ME->isArrow() ? "->" : ".";
                base = ME->getBase();
            }
            else{
                base = ME;
            }
        }
       
        std::string StructType = getTypeFromExpr(base);
        
        if (StructType.empty() or FieldName.empty())
            return "";

        return Array + Ampersand + StructType + Separator + FieldName;
    }

    
    std::string StatsVarInit(VarDecl *VD){
        std::stringstream stream;
        stream << GetVarName(VD);
        stream << " (ME: " << GS->VarInitFromME[VD].size();
        stream << " Param/Global/Call: " << GS->VarInitFromD.count(VD);
        stream << " ContainerOf:" << GS->VarInitContainerOf.count(VD) << ")";
        return stream.str();
    }

    Decl *HandleVar(VarDecl *VarD, std::list<std::string>* result,
                    std::set<VarDecl *> *alreadyProcessedVDs = NULL, bool CheckDuplicates=true) {

        if (alreadyProcessedVDs == NULL)
            alreadyProcessedVDs = new std::set<VarDecl*>;
        
        if(GS->VarInitFromME.count(VarD) and alreadyProcessedVDs->count(VarD) == 0){
            for(MemberExpr *initME: GS->VarInitFromME[VarD]){
                alreadyProcessedVDs->insert(VarD);
                if (GS->VarInitContainerOf.count(VarD) == 0){
                    // If this is the last element we return, otherwise we just recurse.
                    if (GS->VarInitFromME[VarD].back() == initME)
                        return HandleMemberExpr(initME, result, alreadyProcessedVDs, false);
                    else
                        HandleMemberExpr(initME, result, alreadyProcessedVDs, false);
                }
                    
                else{
                    bool contains = false;
                    StmtContainsExpr(initME, GS->VarInitContainerOf[VarD], &contains);
                    if(!contains){
                        AppendContainerOf(GS->VarInitContainerOf[VarD], result, 1);
                        return HandleMemberExpr(initME, result, alreadyProcessedVDs, false);
                    }                   
                    else{
                        Decl *Ret = HandleMemberExpr(initME, result, alreadyProcessedVDs, false);
                        AppendContainerOf(GS->VarInitContainerOf[VarD], result, 1);
                        return Ret;
                    }
                        
                }
            }
        }

        if(GS->VarInitContainerOf.count(VarD)){
            AppendContainerOf(GS->VarInitContainerOf[VarD], result, 1);
        }

        if(GS->VarInitFromD.count(VarD)){
            if(isValidSource(GS->VarInitFromD[VarD]))
                return GS->VarInitFromD[VarD];
            else
                return NULL;
        }
            
        if(VarD->hasGlobalStorage() or isa<ParmVarDecl>(VarD)){
            if(GS->VarID.count(VarD) == 0)
                GS->VarID[VarD] = id();
            return VarD;
        }
        
        return NULL;
    }
        
    // This is one of the main function of our analysis: it takes a MemberExpr and fills the result list.
    // To do so, it needs to traverse in depth the tree rooted at ME.
    // If while traversing we encounter a:
    // 1. Another MemberExpr we recurse, except in the case it was initialized or anonymous
    // 2. A CallExpr to an inline function we visit it and then recurse if the function returns a ME, or continue if it returns a variable
    // 3. If we meet a DRE (and its corrispective Decl) or we got a Decl from 1. or 2. then we check how this variable was initialized: if it was from a ME itself we recurse, if it was from another variable we return it..
    
    Decl* HandleMemberExpr(MemberExpr *ME, std::list<std::string>* result,
                           std::set<VarDecl *> *alreadyProcessedVDs = NULL, bool CheckDuplicates=true){

        if(GS->AlreadyProcessedMEs.count(ME) and CheckDuplicates)
            return NULL;    
        GS->AlreadyProcessedMEs.insert(ME);
        
        std::string res = ExtractStructAndField(ME);

        DEBUG("Found", res);

        if(res == "")
            return NULL;

        DEBUG("Appending", res, "\n");
        result->push_front(res);

        // Here we traverse only in depth.
        Stmt *base = ME;
        while(base->children().begin() != base->children().end()){
            Decl *D = NULL;
            base = *(base->children().begin());
            if(!base)
                break;
            
            if(MemberExpr* BaseME = dyn_cast<MemberExpr>(base)){
                GS->AlreadyProcessedMEs.insert(BaseME);

                if (isAnonStructOrUnion(BaseME))
                    continue;

                // Was the ME initialized?
                MemberExpr *MeInit = GetMEInitME(BaseME);
                if(MeInit){
                    return HandleMemberExpr(MeInit, result, alreadyProcessedVDs, false);
                }
                D = GetMEInitD(BaseME);
                if(!D)
                    return HandleMemberExpr(BaseME, result, alreadyProcessedVDs, false);
            }

            // inet_sk(isk)->sk_flags = 0;
            // if(CallExpr *CE = dyn_cast<CallExpr>(base)){
            //     if(FunctionDecl *FD = CE->getDirectCallee()){
            //         if(SupportedInlineFunctions(FD)){
            //             VarInit* VI = (struct VarInit *) calloc(1, sizeof(struct VarInit));;
            //             TraverseInlineFunction(CE, VI);
            //             D = VI->D;
            //         }
            //     }
            // }

            if(DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(base))
                D = DRE->getDecl();

            // If we got up to this point without a Decl we just continue..
            if (!D)
                continue;
            
            if(dyn_cast<FunctionDecl>(D))
                return D;

            VarDecl *VarD = dyn_cast<VarDecl>(D);
            if(!VarD)
                continue;
            
            DEBUG("Found var:", StatsVarInit(VarD));
            return HandleVar(VarD, result, alreadyProcessedVDs, CheckDuplicates);                        
        }
        
        return NULL;
    }

    void LogAccess(Expr *Loc, Decl *Source, std::list<std::string> resultList){
        Json::Value Access = CreateJsonAccess(Loc, Source, resultList);        
        CurrentJson["accesses"].append(Access);            
    }
    
    Json::Value CreateJsonAccess(Stmt *Loc, Decl *Source, std::list<std::string> resultList, bool isRef=false){        
        Json::Value Access;
        std::string VarId = std::to_string(GS->VarID[dyn_cast_or_null<VarDecl>(Source)]);
        std::string result = join(resultList, '|');
        
        if(!Source){
            Access = MapToJson({{"type", "normal"}});
            // LOG_ACCESS("[NORMAL]", GetFunctionInfo(MainFD), GetStmtBegin(Loc), result, "-1");
        }
        
        else if (FunctionDecl *InitFD = dyn_cast<FunctionDecl>(Source)){
            Access = MapToJson({
                    {"type", "retval"},
                    {"source", GetFunctionName(InitFD)},
                    {"var_id", "-1"}
                });
            // LOG_ACCESS("[RETVAL]", GetFunctionInfo(MainFD), GetStmtBegin(Loc), result, GetFunctionName(InitFD), "-1");
        }
        
        else if (ParmVarDecl *PVD = dyn_cast<ParmVarDecl>(Source)){            
            // PVD->dump();
            // llvm::errs() << "ASDF " << isPtrOfPtr(PVD) << "\n";
            std::string ParamPos = std::to_string(GetParmPosition(MainFD, PVD));
            
            Access = MapToJson({
                    {"type", "param"},
                    {"source", ParamPos},
                    {"var_id", VarId},
                    {"ptr2ptr", std::to_string(isPtrOfPtr(PVD))}
                });        
            // LOG_ACCESS("[PARAM]", GetFunctionInfo(MainFD), GetStmtBegin(Loc), result, ParamPos, VarId);
        }
        
        else if (VarDecl *VD = dyn_cast<VarDecl>(Source)){
            if (VD->hasGlobalStorage()){
                Access = MapToJson({
                        {"type", "global"},
                        {"source", GetVarName(VD)},
                        {"var_id", VarId}
                    });
                // LOG_ACCESS("[GLOBAL]", GetFunctionInfo(MainFD), GetStmtBegin(Loc), result, GetVarName(VD), VarId);
            }            
        }                
        else
            llvm_unreachable("Strange! The source of this access is nor a function or a parameter or a global variable..");
    
        Access["line"] = GetStmtBegin(Loc);
        Access["ref"] = isRef;
        if(resultList.size())
            Access["chain"] = ListToJson(resultList);
        else
            Access["chain"] = Json::arrayValue;
        
        return Access;

    }

    // If this function returns false, then we don't explore any other child..
    bool ExploreMemberExpr(MemberExpr *ME){
        Decl *Source;
        std::string result;
        std::list<std::string> resultList;
        
        Source = HandleMemberExpr(ME, &resultList);

        if(resultList.empty())
            return false;
        
        LogAccess(ME, Source, resultList);

        if(GS->DeferredVarInit.first){
            LoadVarInit(NULL, GS->DeferredVarInit.first, GS->DeferredVarInit.second, false);
            GS->DeferredVarInit.first = NULL;
        }

        return true;
    }

        
    bool areMEsEquals(MemberExpr *ME1, MemberExpr *ME2){
        VarInit *VarInit1 = FindVarInit(ME1);
        VarInit *VarInit2 = FindVarInit(ME2);
        
        if (ExtractStructAndField(ME1) != ExtractStructAndField(ME2))
            return false;

        VarDecl *VD1 = VarInit1->VD;
        VarDecl *VD2 = VarInit2->VD;

        if (not VD1 or not VD2)
            return false;
        
        if ((VD1 == VD2) or
            (GS->VarInitFromD.count(VD1) and GS->VarInitFromD[VD1] == VD2) or
            (GS->VarInitFromD.count(VD2) and GS->VarInitFromD[VD2] == VD1))
            return true;
        else
            return false;
    }
    
    Decl* GetMEInitD(MemberExpr *ME){
        for (auto &elem : GS->MEInitFromDecl)
            if(areMEsEquals(ME, elem.first))
                return elem.second;
        
        return NULL;
    }

    MemberExpr* GetMEInitME(MemberExpr *ME){
        for (auto &elem : GS->MEInitFromME){
            if(areMEsEquals(ME, elem.first)){
                if (not areMEsEquals(ME, elem.second)) // Recursive referencing?
                    return elem.second;
            }
        }
        
        return NULL;
    }

    void LoadMemberExprInit(MemberExpr *Target_ME, Expr* Init){
        VarInit *VI = FindVarInit(Init);
        if(VI->ME){
            // This is to avoid self referentials ME..
            VarInit *VI1 = FindVarInit(VI->ME);
            VarInit *VI2 = FindVarInit(Target_ME);
            VarDecl *VD1 = VI1->VD;
            VarDecl *VD2 = VI2->VD;
            
            if (not VD1 or not VD2)
                return;
        
            if (VD1 == VD2)
                return;
            
            GS->MEInitFromME[Target_ME] = VI->ME;
        }
        
        else if(VI->D){
            GS->MEInitFromDecl[Target_ME] = VI->D;
        }
    }

    void CopyVarInit(VarDecl *TargetVD, VarDecl* OtherVD){
        DEBUG("Copy:", GetVarName(TargetVD), "<-", GetVarName(OtherVD));
        if (GS->VarID.count(OtherVD) == 0)
            GS->VarID[OtherVD] = id();
        
        GS->VarID[TargetVD] = GS->VarID[OtherVD];
        
        if(GS->VarInitFromME.count(OtherVD) > 0)
            GS->VarInitFromME[TargetVD] = GS->VarInitFromME[OtherVD];

        if(GS->VarInitContainerOf.count(OtherVD) > 0)
            GS->VarInitContainerOf[TargetVD] = GS->VarInitContainerOf[OtherVD];

        if(GS->VarInitFromD.count(OtherVD) > 0)
            GS->VarInitFromD[TargetVD] = GS->VarInitFromD[OtherVD];
        else
            GS->VarInitFromD[TargetVD] = OtherVD;
    }
    
    void ApplyVarInitGlobalState(VarDecl *TargetVD, VarInit *VI, Expr* Init, bool defer){
        OffsetOfExpr *InitOE = VI->OE;
        MemberExpr *InitME = VI->ME;
        Decl *InitD = VI->D;
        VarDecl *InitVD = VI->VD;
        FunctionDecl *InitFD = VI->FD; 

        // llvm::errs() << "FindVarInit returned ME:  " << VI->ME << " VD:  " << VI->VD << " FD:  " << VI->FD << "\n";
        // This happens when a variable is initialized to NULL.
        if(not InitD and not InitME and not InitOE){
            GS->VarInitFromME.erase(TargetVD);
            GS->VarInitFromD.erase(TargetVD);
            GS->VarInitContainerOf.erase(TargetVD);
        }

        // A variable is overriding itself (vma = vma->vm_next). Since
        // we run before HandleMemberExpr, we defer the work after it.
        // else if((InitVD == TargetVD) and InitME and defer){
        //     // GS->DeferredVarInit = std::make_pair(TargetVD, Init);
        //     // DEBUG("Deferring!\n");
        //     1;
        // }
        
        else if(InitME){
            DEBUG("Setting init of", GetVarName(TargetVD), "from ME");
            if(InitVD != TargetVD)
                GS->VarInitFromME.erase(TargetVD);
            GS->VarInitFromME[TargetVD].push_front(InitME);
        }

        else if(InitFD){
            DEBUG("Setting init of", GetVarName(TargetVD), "from FD");
            GS->VarInitFromD[TargetVD] = InitFD;
            GS->VarInitFromME.erase(TargetVD);
        }


        else if(InitVD){
            DEBUG("Setting init of", GetVarName(TargetVD), "from", StatsVarInit(InitVD));
            GS->VarInitFromME.erase(TargetVD);
            CopyVarInit(TargetVD, InitVD);
        }

        if(InitOE){
            DEBUG("Setting init of", GetVarName(TargetVD), "from E\n");
            GS->VarInitContainerOf[TargetVD] = InitOE;
        }
        else
            GS->VarInitContainerOf.erase(TargetVD);
        
    }

    void RestartTraverseFunction(Stmt *S, Stmt *From){
        bool found = false;
        _RestartTraverseFunction(S, From, &found);
    }
    
    void _RestartTraverseFunction(Stmt *S, Stmt *From, bool *found){
        for (auto &c: S->children()){
            if(not c)
                continue;

            if(c == From){
                *found = true;
                continue; // We skip the From node and all of its childs..
            }
        
            if(*found)
                TraverseFunction(c);
            else
                _RestartTraverseFunction(c, From, found);
        }
    }
    
    
    // Sets how TargetVD is initialized.
    void LoadVarInit(Stmt *S, VarDecl *TargetVD, Expr* Init, bool defer){
        DEBUG("Searching for the init of", GetVarName(TargetVD), "in", Init);
        VarInit *VI = FindVarInit(Init);        
        ApplyVarInitGlobalState(TargetVD, VI, Init, defer);        
    }
    
    void ExploreCallExpr(CallExpr *CE){
        FunctionDecl *FD = CE->getDirectCallee();
        if(not FD or IgnoreFunction(FD))
            return;

        Json::Value Call;

        while(FD and !FD->isThisDeclarationADefinition())
            FD = FD->getPreviousDecl();

        if (!FD)
            FD = CE->getDirectCallee();
        
        // DEBUG("Exploring in ", GetFunctionName(MainFD), " CallExpr:", CE, GetFunctionName(FD));

        Call = MapToJson({
                {"line", GetStmtBegin(CE)},
                {"callee", GetFunctionName(FD)},
                {"callee_filename", GetDeclFilename(FD)}
            });

        for(unsigned int i=0; i < CE->getNumArgs(); i++){
            Expr *Arg = CE->getArg(i);
            VarInit *VI = FindVarInit(Arg);
            // If the function is only a prototype then all the parameters are marked as unused.
            // The first check if for varargs functions
            if (FD->isThisDeclarationADefinition() and i < FD->getNumParams() and not FD->getParamDecl(i)->isUsed()){
                GS->AlreadyProcessedMEs.insert(VI->ME);
                continue;
            }
            
            if(VI->ME){
                std::list<std::string> resultList;
                Decl *Source = HandleMemberExpr(VI->ME, &resultList, NULL, false);             
                Json::Value Access = CreateJsonAccess(VI->ME, Source, resultList);
                Access["position"] = std::to_string(i);
                Call["args"].append(Access);
            }
            
            else if(VI->VD and (isDeclStructPtr(VI->VD) or isDeclVoidPointer(VI->VD))){
                std::list<std::string> resultList;
                Decl *Source = HandleVar(VI->VD, &resultList);                
                Json::Value Access = CreateJsonAccess(CE, Source, resultList);
                Access["position"] = std::to_string(i);
                Call["args"].append(Access);     
            }
            
            else if(VI->FD and GetFunctionName(VI->FD) == "get_current"){
                std::list<std::string> resultList;
                Json::Value Access = CreateJsonAccess(CE, VI->FD, resultList);
                Access["position"] = std::to_string(i);
                Call["args"].append(Access);
            }
        }
        
        CurrentJson["calls"].append(Call);       
    }
    
    void ExploreBinaryOperator(BinaryOperator *BO){
        if(BO->isAssignmentOp()){
            if(DeclRefExpr *DRE = dyn_cast_or_null<DeclRefExpr>(BO->getLHS())){
                if(VarDecl *VD = dyn_cast_or_null<VarDecl>(DRE->getDecl()))
                    if(isDeclStructPtr(VD) or isDeclVoidPointer(VD)){
                        LoadVarInit(BO, VD, BO->getRHS(), true);
                    }
            }

            // file->f_op = new_fops;
            if(MemberExpr *ME = dyn_cast_or_null<MemberExpr>(BO->getLHS()))
                LoadMemberExprInit(ME, BO->getRHS());
        }
    }

    void ExploreDeclStmt(DeclStmt *DS){
        for(Decl *D: DS->decls()){
            if(VarDecl *VD = dyn_cast<VarDecl>(D))
                if(VD->hasInit() and (isDeclStructPtr(VD) or isDeclVoidPointer(VD)))
                    LoadVarInit(DS, VD, VD->getInit(), true);
        }
    }

    void StmtContainsExpr(Stmt *S, Expr *OE, bool *contains){
        if(!S)
            return;
        if(S == OE)
            *contains = true;

        for (Stmt *c: S->children())
            StmtContainsExpr(c, OE, contains);
    }
    
    void AppendReturns(){
        for(auto &R: getReturns(MainFD)){
            VarInit *VI = FindVarInit(R);
            bool oe_under_me = false;
            if(VI->ME){
                std::list<std::string> resultList;
                Decl *Source = HandleMemberExpr(VI->ME, &resultList, NULL, false);

                if (VI->OE){
                    oe_under_me = false;
                    StmtContainsExpr(VI->ME, VI->OE, &oe_under_me);
                    if (oe_under_me == true){
                        AppendContainerOf(VI->OE, &resultList, 1);
                    }
                    else{
                        AppendContainerOf(VI->OE, &resultList, 0);
                    }
                }

                Json::Value Return = CreateJsonAccess(VI->ME, Source, resultList);
                CurrentJson["returns"].append(Return);
            }
            else if(VI->VD and (isDeclStructPtr(VI->VD) or isDeclVoidPointer(VI->VD))){
                std::list<std::string> resultList;
                Decl *Source = HandleVar(VI->VD, &resultList);
                if(VI->OE){
                    AppendContainerOf(VI->OE, &resultList, 0);
                }

                Json::Value Return = CreateJsonAccess(R, Source, resultList);
                CurrentJson["returns"].append(Return);
            }
            else if(VI->FD){
                std::list<std::string> resultList;
                Json::Value Return = CreateJsonAccess(R, VI->FD, resultList);
                CurrentJson["returns"].append(Return);
            }
            
        }
    }

    std::vector<ReturnStmt*> getReturns(FunctionDecl *FD){
        std::vector<ReturnStmt*> Returns;
        if (FD->hasBody())
            _getReturns(FD->getBody(), &Returns);
        return Returns;
    }


    void _getReturns(Stmt *S, std::vector<ReturnStmt*> *Returns){
        if (!S)
            return;
        for (Stmt *c: S->children()){
            if(ReturnStmt *RS = dyn_cast_or_null<ReturnStmt>(c)){
                Returns->push_back(RS);
                // Expr *Ret = RS->getRetValue();
                // if(Ret and not Ret->isNullPointerConstant(*Context, Expr::NPC_NeverValueDependent))
                //     Returns->push_back(Ret);
            }
            else
                _getReturns(c, Returns);
        }
    }


    // This function takes a CallExpr to a function which might be inlined by the compiler.
    // Handling them requires 3 different actions:
    // 1. We load the init of parameters from the arguments given by the CallExpr.
    // 2. We visit the body of the function, thus loading the Init of local variables
    // 3. We create a fake VD and initialize it with the ReturnStmt of the inline function.
    //    We then set the VI passed to this function to the fake VD just created.

    

    VarInit* FindVarInit(Stmt *S){
        VarInit* VI = (struct VarInit *) calloc(1, sizeof(struct VarInit));
        _FindVarInit(S, VI);
        VI->VD = dyn_cast_or_null<VarDecl>(VI->D);
        VI->FD = dyn_cast_or_null<FunctionDecl>(VI->D);        
        return VI;
    }
    
    // This function finds how a variable is initialized, exploring the tree rooted at S.
    void _FindVarInit(Stmt *S, VarInit *VI){

        if(!S)
            return;
        
        // CompoundStmt contains the body of a macro. Since they can
        // define variables, assing and dereference fields, we treat
        // them as functions.
        // For example: s = container_of(s->sk_node.next, struct sock, sk_node);
        if(isa<CompoundStmt>(S)){
            TraverseFunction(S);
            GS->AlreadyProcessedCSs.insert(S);
            _FindVarInit(dyn_cast<CompoundStmt>(S)->body_back(), VI);
        }
        
        // container_of
        if(BinaryOperator *BO = dyn_cast<BinaryOperator>(S)){
            if(BO->getOpcodeStr() == "-"){                
                if(OffsetOfExpr *OE = dyn_cast_or_null<OffsetOfExpr>(BO->getRHS())){
                    VI->OE = OE;
                }
                _FindVarInit(BO->getLHS(), VI);
                return;
            }
        }

        // XXX: here we should check which of the two Expr contains NULL (if any) and choose the other one.
        // Example of conditional operator: (((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
        if(ConditionalOperator *CO = dyn_cast<ConditionalOperator>(S)){
            _FindVarInit(CO->getTrueExpr(), VI);
            // FindVarInit(CO->getFalseExpr(), ME, D);
            return;
        }

        if(ArraySubscriptExpr *ASE = dyn_cast<ArraySubscriptExpr>(S)){
            _FindVarInit(ASE->getBase(), VI);
            return;
        }

        
        if(dyn_cast<MemberExpr>(S) and not VI->ME){
            VI->ME = dyn_cast<MemberExpr>(S);
        }
        
        if(CallExpr *CE = dyn_cast<CallExpr>(S)){
            if(FunctionDecl *FD = CE->getDirectCallee()){
                if(IgnoreFunction(FD))
                    return;                
                VI->D = FD;
                return;
            }
        }

        if(DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)){
            if(VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())){
                VI->D = VD;
                return;
            }
        }

        for (Stmt *c: S->children())
            if(c)
                _FindVarInit(c, VI);
    }

    bool ContainsSwitchStmt(Stmt *S){
        bool contains = false;
        _ContainsSwitchStmt(S, &contains);
        return contains;
    }
    
    void _ContainsSwitchStmt(Stmt *S, bool *contains){
        if(not S)
            return;

        if(SwitchStmt *SS = dyn_cast<SwitchStmt>(S)){
            Expr *Cond = SS->getCond();
            if(isa<ParenExpr>(Cond))
                Cond = dyn_cast<ParenExpr>(Cond)->getSubExpr();
            // dyn_cast<SwitchStmt>(S)->getCond()->dump();
            // sizeof switch cases are fine.
            if (!isa<UnaryExprOrTypeTraitExpr>(Cond))
                *contains = true;
        }
        
        for (auto &c: S->children()){
            if(c)                
                _ContainsSwitchStmt(c, contains);
        }
    }
    void TraverseFunction(Stmt *S){
        if(not S)
            return;

        // Some CompoundStmt are already traversed by _FindVarInit, so if it is the case we just skip them.
        if(isa<CompoundStmt>(S) and GS->AlreadyProcessedCSs.count(S) != 0){
            return;
        }
        
        if(DeclStmt *DS = dyn_cast<DeclStmt>(S)){
            ExploreDeclStmt(DS);
        }

        if(BinaryOperator *BO = dyn_cast<BinaryOperator>(S)){
            TraverseFunction(BO->getLHS());                        
            TraverseFunction(BO->getRHS());
            ExploreBinaryOperator(BO);
            return;
        }

        if(MemberExpr *ME = dyn_cast<MemberExpr>(S)){
            if (not ExploreMemberExpr(ME))
                return;
        }

        // This handles cases like: if (0) {}, generated for example from the noprintk macro..
        if(IfStmt *IS = dyn_cast<IfStmt>(S)){
            if(isIfZero(IS))
                return;
            
            // TraverseFunction(IS->getCond());

            // GlobalState *GS2 = CopyGlobalState(GS);
            // GlobalState *PreviousGS = GS;
            // GS = GS2;
            // llvm::errs() << "IF Traversing THEN\n";
            // TraverseFunction(IS->getThen());
            // // Restart just after the else.
            // llvm::errs() << "IF Restarting after the IF\n";
            // RestartTraverseFunction(MainFD->getBody(), IS->getElse());

            // GS = PreviousGS;
            // llvm::errs() << "IF Traversing ELSE\n";
            // TraverseFunction(IS->getElse());            
            // return;
        }

        if(ForStmt *FS = dyn_cast<ForStmt>(S)){
            TraverseFunction(FS->getInit());
            TraverseFunction(FS->getCond());
            TraverseFunction(FS->getBody());
            TraverseFunction(FS->getInc());
            return;
        }

        if(CallExpr *CE = dyn_cast<CallExpr>(S)){
            if(SkipCallArguments(CE))
                return;

            ExploreCallExpr(CE);
        }
        
        for (auto &c: S->children()){
            if(c)                
                TraverseFunction(c);
        }
    }

    bool VisitVarDecl(VarDecl *VD){
        if (DEBUG_FUNCTION != "")
            return true;

        if(GetVarName(VD).find("FAKE_RANDOMIZE_LAYOUT") == 0){
            Json::Value Root;
            Root["type"] = "RANDOMIZE";
            Root["struct_type"] = getQTypeStr(VD->getType());
            Log(Root);
        }

        // VD->getType()->dump();
        // untyped global variables, es: tk_core
        if (VD->getType()->isRecordType() and VD->getType()->hasUnnamedOrLocalType()){
            RecordDecl *RD = VD->getType()->getAsRecordDecl();
            VisitRecordDecl(RD, "struct ANON_" + GetVarName(VD));
        }

        if (VD->hasGlobalStorage()){
            const Type *T = VD->getType()->getPointeeOrArrayElementType();
            if(T->isPointerType() or VD->getType()->isPointerType()){
                Json::Value Root;
                Root["type"] = "GLOBAL_PTR";
                Root["name"] = GetVarName(VD);
                Log(Root);
            }
            if(VD->getType()->isArrayType()){
                Json::Value Root;
                Root["type"] = "GLOBAL_ARR";
                Root["name"] = GetVarName(VD);
                Log(Root);
            }

        }

        return true;
    }

    bool VisitFunctionDecl(FunctionDecl *FD) {        
        if (!FD->hasBody() or !FD->isThisDeclarationADefinition())
            return true;

        if (DEBUG_FUNCTION != ""){
            if(GetFunctionName(FD) != DEBUG_FUNCTION)
                return true;
            else
                FD->dump();
        }

        if(ContainsSwitchStmt(FD->getBody())){
            ALOG("-------------- Skipping " + GetFunctionName(FD) + " because it contains a switch case");
            return true;
        }
        
        ALOG("################### " + GetFunctionName(FD));
        MainFD = FD;
        CurrentJson = MapToJson({
                {"type", "FUNCTION_DECL"},
                {"filename", GetDeclFilename(FD)},
                {"name", GetFunctionName(FD)},
                {"start", GetDeclBegin(FD)},
                {"end", GetDeclEnd(FD)}
            });

        GS = new GlobalState;
        
        for(ParmVarDecl *PDS : FD->parameters())
            GS->VarID[PDS] = id();

        PM = new ParentMap(FD->getBody());
        TraverseFunction(FD->getBody());
        AppendReturns();
        
        Log(CurrentJson);
        
        return true;
    }

private:
    ASTContext *Context;
    FunctionDecl *MainFD;
    GlobalState *GS;
    ParentMap *PM;
    Json::Value CurrentJson;
};

class FindNamedClassConsumer : public ASTConsumer {
public:
    explicit FindNamedClassConsumer(ASTContext *Context)
        : Visitor(Context) {}

    virtual void HandleTranslationUnit(ASTContext &Context) {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
private:
    FindNamedClassVisitor Visitor;
};

class FindNamedClassAction : public PluginASTAction {
protected:
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        CompilerInstance &Compiler, llvm::StringRef InFile) override {
        return std::unique_ptr<ASTConsumer>(
        new FindNamedClassConsumer(&Compiler.getASTContext()));
    }

    bool ParseArgs(const CompilerInstance &CI,
                   const std::vector<std::string> &args) override {
        return true;
    }

};

static FrontendPluginRegistry::Add<FindNamedClassAction>
X("my-plugin", "Extract access chains");

