import argparse
import sys

class MyParser(argparse.ArgumentParser):

    # Override the error function of argpase in order to display the help in case of error
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)