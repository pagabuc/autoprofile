
using namespace clang;

std::stringstream log_stream; 

std::string replace_first_pipe(std::stringstream *stream){
    std::string s = stream->str();
    std::size_t found = s.find('|');
    if (found != std::string::npos)
        s[found] = ' ';
    return s;
}

template <typename T>
void ALOG(T e) {
    std::stringstream tmp_stream;
    tmp_stream << e << "\n";   
    llvm::errs() << tmp_stream.str();
}

template <typename T>
void LOG(T e) {
    std::stringstream tmp_stream;
    tmp_stream << "\n" << replace_first_pipe(&log_stream) << e << "\n";   
    llvm::errs() << tmp_stream.str();
    log_stream.str("");
}

template <typename T, typename... Args>
void LOG(T e, Args... args) {
    log_stream << e << "|";
    LOG(args...);
}

template <typename T, typename... Args>
void LOG_ACCESS(T e, Args... args) {
    log_stream << "[ACCESS]";
    LOG(e, args...);
}

template <typename T>
void DEBUG(T e) {
    log_stream << e << "\n";
    // llvm::errs() << log_stream.str();
    log_stream.str("");
}

template <typename T, typename... Args>
void DEBUG(T e, Args... args) {
    log_stream << e << " ";
    DEBUG(args...);
}

inline bool ends_with(std::string const & value, std::string const & ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}


std::string join(std::list<std::string>& v, char c) {
    std::string s = std::to_string(v.size()) + c;
    for (auto p = v.begin(); p != v.end(); ++p) {
        s += *p;
        if (std::next(p) != v.end())
            s += c;
    }
    return s;      
}

bool isAnonStructOrUnion(MemberExpr *ME){
    return dyn_cast<FieldDecl>(ME->getMemberDecl())->isAnonymousStructOrUnion();
}

QualType getQualType(const Type *T){
    QualType QT;
    if (T->isRecordType()){
        const RecordType *RT = T->getAsStructureType();
        QT = RT->desugar();
    }
    else{
        QT = T->getPointeeType();
    }
    return QT;
}

std::string getTypeFromRecordDecl(RecordDecl *RD){
    const Type *T = RD->getTypeForDecl();
    QualType QT = getQualType(T);
    return QT.getAsString();
}

std::string GetFunctionName(FunctionDecl *FD){
    return FD->getNameInfo().getAsString();
}

std::string GetVarName(VarDecl *VD){
    if (not VD)
        return "NULL";   
    return VD->getDeclName().getAsString();
}

int GetParmPosition(FunctionDecl *FD, VarDecl *PVD){
    for(unsigned int i = 0; i < FD->getNumParams(); i++){
        if(FD->getParamDecl(i) == PVD){
            return i;
        }
    }
    return -1;
}

bool isValidSource(Decl *D, FunctionDecl *FD = NULL){
    if(not D)
        return false;
                
    if(isa<FunctionDecl>(D))
        return true;

    if (isa<ParmVarDecl>(D) and FD == NULL)
        return true;

    if (isa<ParmVarDecl>(D) and FD and (GetParmPosition(FD, dyn_cast<VarDecl>(D)) >= 0))
        return true;

    if(VarDecl *VD = dyn_cast<VarDecl>(D))
        if(VD->hasGlobalStorage())
            return true;
        
    return false;
}


bool SkipCallArguments(CallExpr *CE){
    if (FunctionDecl *callee = dyn_cast_or_null<FunctionDecl>(CE->getCalleeDecl())){
        if(GetFunctionName(callee).find("trace_") == 0 || GetFunctionName(callee).find("kdebug") == 0)
            return true;
    }
    return false;
}

    

bool IgnoreFunction(FunctionDecl *FD){
    if(GetFunctionName(FD).find("__read_once") == 0 ||
       GetFunctionName(FD).find("__compiletime") == 0 ||
       GetFunctionName(FD).find("__builtin_constant_p") == 0 ||
       GetFunctionName(FD).find("__bad_size_call_parameter") == 0 ||
       GetFunctionName(FD).find("__builtin_expect") == 0 ||
       GetFunctionName(FD).find("__bad_percpu_size") == 0)
        return true;
    return false;
}


bool isDeclStructPtr(ValueDecl *D){
    QualType QT = D->getType();
    return QT->isPointerType() && QT->getPointeeType()->isStructureType();
}

bool isDeclVoidPointer(ValueDecl *D){
    return D->getType()->isVoidPointerType();
}

bool isPtrOfPtr(ValueDecl *D){
    QualType QT = D->getType();
    return D->getType()->isPointerType() and QT->getPointeeType()->isPointerType();
}


bool FunctionDeclHasBody(FunctionDecl *FD){
    return FD and FD->hasBody();
}
