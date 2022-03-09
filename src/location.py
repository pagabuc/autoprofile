from utils import normfunc

class Location:
    def __init__(self, filename, function, line):
        self.filename = filename
        self.function = normfunc(function)
        self.line = int(line)

    # def __iter__(self):
    #     yield from [self.filename, self.function, self.line]

    def __lt__(self, other):
        return (self.filename, self.function, self.line) < (other.filename, other.function, other.line)

    def __repr__(self):
        return "%s:%s:%s" % (self.filename, self.line, self.function)

    def __hash__(self):
         return hash(repr(self))

    def __eq__(self, other):
        return repr(self) == repr(other)

    def same_function(self, other):
        return (self.filename == other.filename and self.function == other.function)


if __name__ == "__main__":
    a = Location("foo.c", "foo", 10)
    b = Location("foo.c", "foo", 1)
    c = Location("baz.c", "baz", 1)
    d = Location("baz.c", "xxx", 10)
    e = Location("baz.c", "baz", 20)
    print(sorted([e,d,a,b,c]))
