import os
import subprocess
import json
import re
import shutil
import sys

from multiprocessing import Pool, Manager

ROOT     = os.path.dirname(__file__)
COMPILER = os.path.join(ROOT, "clang-profile")
PPTRACE  = os.path.join(ROOT, "clang/llvm-build/bin/pp-trace")
PPTRACE_IGNORE= """FileChanged,FileSkipped,FileNotFound,InclusionDirective,moduleImport,EndOfMainFile,Ident,PragmaDirective,PragmaComment,PragmaDetectMismatch,PragmaDebug,PragmaMessage,PragmaDiagnosticPush,PragmaDiagnosticPop,PragmaDiagnostic,PragmaOpenCLExtension,PragmaWarning,PragmaWarningPush,PragmaWarningPop,MacroDefined,MacroUndefined,Defined,SourceRangeSkipped,If,Ifdef,Ifndef,Else,Elif"""

PLUGIN_OUTPUT_TYPES = ['"type":"FUNCTION_DECL"', '"type":"RECORD"', '"type":"RANDOMIZE"', '"type":"GLOBAL_ARR"', '"type":"GLOBAL_PTR"']
UNKNOWN_ARGS = Manager().list()

def grep_pptrace_output(stderr):
    output = set()
    for l in stderr.split("\n"):
        if '"Callback":' in l:
            output.add(l)
    return output

def grep_plugin_output(stderr):
    output = set()
    for l in stderr.split("\n"):
        if any(i in l for i in PLUGIN_OUTPUT_TYPES):
            output.add(l)
    return output

def append_unknown_args(stderr):
    r = re.compile("error: unknown argument: '(.*)'")
    for x in stderr.split("\n"):
        match = r.search(x)
        if match and match.group(1) not in UNKNOWN_ARGS:
            UNKNOWN_ARGS.append(match.group(1))

def clean_entry(entry):
    args = entry[1:]
    return [a for a in args if a not in UNKNOWN_ARGS]

def clang_entry(entry):
    args = [COMPILER] + clean_entry(entry)
    return run_subprocess(args)

def pptrace_entry(entry, unknown=None):
    args = clean_entry(entry)
    filename = args[-1]
    arguments = args[:-1]
    args = [PPTRACE, "-json", "-ignore=%s" % PPTRACE_IGNORE]  + [filename] + arguments
    return run_subprocess(args)


def run_subprocess(args):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return p, stdout.decode() + stderr.decode()

# If the first run fails (most probably because it complains about
# unknown arguments) then we try to compile the file again without
# those arguments.
def compile_entry(entry):
    p, clang_stderr = clang_entry(entry)
    p1, pptrace_stderr = pptrace_entry(entry)

    if p.returncode != 0:
        append_unknown_args(clang_stderr)
        p, clang_stderr = clang_entry(entry)
        p1, pptrace_stderr = pptrace_entry(entry)

        # if p.returncode != 0:
        #     print("\nFailed to compile: %s" % entry[-1])
        #     print("\nFailed to compile: %s" % " ".join(clean_entry(entry)))

    return grep_plugin_output(clang_stderr), grep_pptrace_output(pptrace_stderr)

def save_output(filename, output):
    print("\n[+] Saving %s" % filename)
    with open(filename, 'w') as f:
        for p in sorted(output):
            f.write(p+"\n")

def load_database(filename):
    database = [e['arguments'] for e in json.load(open(filename))]

    for entry in database:
        toremove = []
        # print("ORIG: %s" % " ".join(entry))
        for i, param in enumerate(entry):

            if param == "-o":
                if "/tools/" in entry[i+1]:
                    continue
                toremove.append(i)
                toremove.append(i+1)

            if "-DBUILD_STR(s)=#s" in param or (param.startswith("-D") and "_PLUGIN" in param) or param.startswith("-fplugin=") or param == "-DCC_HAVE_ASM_GOTO":
                toremove.append(i)

        for i in sorted(toremove, reverse=True):
            del entry[i]

        yield entry

def main():
    database = list(load_database("compile_commands.json"))

    plugin_outputs = set()
    pptrace_outputs = set()
    print("[+] Running the clang plugin...")
    with Pool() as pool:
        for i, (clang_out, pptrace_out) in enumerate(pool.imap_unordered(compile_entry, database)):
            sys.stderr.write('\rDone %.2f%%' % ((i+1)/len(database) * 100))
            plugin_outputs.update(clang_out)
            pptrace_outputs.update(pptrace_out)

    save_output("plugin.json", plugin_outputs)
    save_output("pptrace.json", pptrace_outputs)

if __name__ == "__main__":

    if not os.path.isfile(COMPILER):
        print("[-] %s not found.." % COMPILER)
        sys.exit(-1)

    if not os.path.isfile(PPTRACE):
        print("[-] %s not found.." % PPTRACE)
        sys.exit(-1)

    if not os.path.isfile("compile_commands.json"):
        print("[-] compile_commands.json not found..")
        sys.exit(-1)

    main()
