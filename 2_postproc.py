import os
import sys

from postproc import main

if __name__ == "__main__":
    filename = os.path.basename(__file__)

    if len(sys.argv) != 2:
        print(f"Usage: python {filename} <result_id>")
        sys.exit(1)

    result_id = sys.argv[1]
    main.start(result_id)