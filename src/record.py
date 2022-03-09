from os.path import abspath as abspath
from os.path import join as joinpath
import logging
import json
import re

l = logging.getLogger('parser')
l.setLevel(logging.DEBUG)


class RecordManager():
    def __init__(self):
        self.records = dict()
        self.fields_offset_zero = set()

    def add_record(self, filename, struct, start, end, body):
        self.records[struct] = Record(filename, struct, start, end, body)

    def iter_zero_records(self):
        for struct, record in self.records.items():
            for field in record.get_fields_offset_zero():
                target = "%s->%s" % (struct, field)
                yield target, record, field

    def get_record(self, struct):
        return self.records[struct]
    
    def is_target_zero(self, target):
        struct, field = target.split("->")
        record = self.records[struct]
        return field in record.get_fields_offset_zero()

    def get_field_type(self, target):
        struct, field = target.split("->")
        record = self.records[struct]
        return record.field_types[field]

    def is_field_pointer(self, target):
        struct, field = target.split("->")
        record = self.records[struct]
        return bool(int(record.field_ptrs[field]))
    
    # XXX: this function must be called on non pointers. 
    def contains_one_non_ptr_field(self, target):
        struct, field = target.split("->")
        t = self.records[struct].field_types[field]
        if "[" in t:
            t = t.split("[")[0].strip()

        return self.count_pointers_struct(t, set())[1] > 0
        
    def count_pointers(self, target):
        struct, field = target.split("->")
        t = self.records[struct].field_types[field]
        size = 1        
        if "[" in t:
            try:
                size = int(re.search("\[(\d+)\]", t).group(1))
            except AttributeError:
                pass            
            t = t.split("[")[0].strip()
        return self.count_pointers_struct(t, set())[0]*size
    
    # This counts how many pointers and how many non pointers fields a structure has - skipping every ifdef fields.
    def count_pointers_struct(self, struct, already):

        if struct in already or struct not in self.records:
            return 0, 0
        
        record = self.records[struct]
        ptrs = 0
        non_ptrs = 0
        for field_name, is_ptr in record.field_ptrs.items():
            if field_name not in record.ifdefs:
                continue
            if int(is_ptr) == 1 and record.ifdefs[field_name] == False:
                ptrs += 1
                
        for field_name, field_type in record.field_types.items():
            # Not a pointer + not ifdef + not nested struct
            if record.field_ptrs[field_name] == "0" and record.ifdefs[field_name] == False and field_type not in self.records:
                non_ptrs += 1
                
            if field_type == struct or record.field_ptrs[field_name] == "1" or record.ifdefs[field_name] == True:
                continue
            
            new_ptrs, new_non_ptrs = self.count_pointers_struct(field_type, already)
            
            ptrs += new_ptrs
            non_ptrs += new_non_ptrs
            already.add(field_type)
        return ptrs, non_ptrs
    
# This stuff is crap, we should emit with  RecursiveVisitRecordDecl(RDD, Field["anon_fields"]);
# and handling it in a nicer way here..
class Record:
    def __init__(self, filename, name, start, end, body):
        self.filename = filename
        self.name = name
        self.start = start
        self.end = end
        self.body = []
        self.field_types = dict()
        self.field_ptrs = dict()
        self.offsets = dict() # This is a list of ('field_name', virtual_offset)
        self.lines = dict()
        self.all_pointers = True

        for f in body:
            name = f["name"]
            line = f["line"]

            self.field_ptrs[name] = f["is_pointer"]
            self.all_pointers &= bool(int(f["is_pointer"]))

            self.body.append((name, int(line)))

            if name != "anon_union" and name != "anon_struct":
                self.lines[name] = int(line)
                l.debug("TY %s->%s = %s pointer: %s" % (self.name, name, f["field_type"], f["is_pointer"]))
                self.field_types[name] = f["field_type"]


        self.assign_offsets_fields()

    def is_field_pointer(self, field):
        return bool(int(self.field_ptrs[field]))
        
    def get_list_head_fields(self):
        lh = set()
        for field, t in self.field_types.items():
            if t == "struct list_head" and not bool(int(self.field_ptrs.get(field, False))):
                lh.add(field)
        return lh
        
    def get_fields_offset_zero(self):
        for f in self.offsets:
            if self.offsets[f] == 0:
                yield f

    def get_line_field(self, field):
        return self.lines[field]

    # Tries to assing an "offset" to each field of a
    # structure.  This offset is used when we do the layout of the structure
    # in z3 (to know the position of a field in respect to others)
    # or when we want to know the first field of a struct.

    # The offsets are generated being aware of anonymous unions/structs.
    # For example:
    # union {      OFFSET
    #   int a;       0
    #   struct {
    #     int b;     0
    #     int c;     1
    #   };
    #   struct {
    #     int e;     0
    #     int f;     2
    # };

    def assign_offsets_fields(self):
        already_parsed_fields = set()
        offset = 0
        for i, (name, size) in enumerate(self.body):
            if name == "anon_union":
                union_body = self.body[i+1:i+1+size]
                for f in self.get_first_fields_union(union_body):
                    self.offsets[f] = offset

            elif name != "anon_struct":
                if name not in self.offsets:
                    self.offsets[name] = offset
                offset += 1

    # Given the body of an union as parameter, it returns all the fields at offset 0 inside this union.
    def get_first_fields_union(self, body):
        i=0
        while i < len(body):
            name, size = body[i]
            if name == "anon_union":
                anon_body = body[i+1:i+1+size]
                for f in self.get_first_fields_union(anon_body):
                    yield f
                i = i+1+size
            elif name == "anon_struct":
                anon_body = body[i+1:i+1+size]
                yield list(self.get_first_fields_union(anon_body))[0]
                i = i+1+size
            else:
                yield name
                i+=1
