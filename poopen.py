import subprocess as sp

# subprocess doesn't come with very useful wrappers,
# so let's write our own!

class PoopenError(sp.CalledProcessError):
    def __init__(self, returncode, cmd, output=None, error=None):
        self.returncode = returncode
        self.cmd = cmd
        self.output = output
        self.error = error
    def __str__(self):
        s = "Command failed with exit status {}:\n{}".format(self.returncode, self.cmd)
        if self.output:
            output = str(self.output, 'utf-8', 'ignore')
            s += "\nstdout:\n{}\n".format(output)
        if self.error:
            error = str(self.error, 'utf-8', 'ignore')
            s += "\nstderr:\n{}\n".format(error)
        return s

def poopen(args, env=None):
    p = sp.Popen(args, stdout=sp.PIPE, stderr=sp.PIPE, env=env)
    out, err = p.communicate()
    if p.returncode != 0:
        raise PoopenError(returncode=p.returncode, cmd=args, output=out, error=err)
    return p.returncode, out, err
