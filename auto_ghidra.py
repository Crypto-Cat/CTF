import os
import sys
import click
import subprocess
import tempfile
import itertools as IT
import select
from time import sleep

# This script was written by liba2k <3 (https://gist.github.com/liba2k/d522b4f20632c4581af728b286028f8f)
# The only thing I've changed is the path + delay, just added here to reduce the regular requests I get for it xD
# Personally, I set a shortcut alias for this in .bash_aliases, like:
# alias ghidra_auto='python3 /home/crystal/apps/auto_ghidra.py'

PROJECT_DIRECTORY = '/tmp'  # For the -t flag
GHIDRA_PATH = '/usr/share/ghidra/'  # Set to your ghidra_path


def uniquify(path, sep=''):
    def name_sequence():
        count = IT.count()
        yield ''
        while True:
            yield '{s}_{n:d}'.format(s=sep, n=next(count))
    orig = tempfile._name_sequence
    with tempfile._once_lock:
        tempfile._name_sequence = name_sequence()
        path = os.path.normpath(path)
        dirname, basename = os.path.split(path)
        filename, ext = os.path.splitext(basename)
        fd, filename = tempfile.mkstemp(dir=dirname, prefix=filename, suffix=ext)
        tempfile._name_sequence = orig
    return filename


def shouldRun():
    click.secho('Will run analysis in 1 second, press any key to cancel', fg='green')
    i, o, e = select.select([sys.stdin], [], [], 1)

    if (i):
        return False
    else:
        return True


@click.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('-t', '--temp', 'temp', is_flag=True)
def main(filename, temp):
    if os.path.isdir(filename):
        return os.system(f'{GHIDRA_PATH}ghidraRun')
    if '.gpr' in filename:
        os.system(f'{GHIDRA_PATH}ghidraRun "{os.path.abspath(filename)}"')
        return
    if temp:
        proj_file = uniquify(os.path.join(PROJECT_DIRECTORY, os.path.basename(filename) + '.gpr'))
        out_dir = PROJECT_DIRECTORY
    else:
        proj_file = uniquify(filename + '.gpr')
        out_dir = os.path.dirname(filename)
        out_dir = out_dir if out_dir != '' else '.'
    proj_name = os.path.splitext(os.path.basename(proj_file))[0]
    file_output = subprocess.check_output(f'file "{filename}"', shell=True).decode('utf8')
    click.secho(file_output, fg='yellow')
    r = shouldRun()
    if r:
        os.system(f'{GHIDRA_PATH}support/analyzeHeadless {out_dir} "{proj_name}" -import "{filename}"')
        os.system(f'{GHIDRA_PATH}ghidraRun "{proj_file}"')


if __name__ == '__main__':
    main()
