# PyNSXv
PyNSXv is a higher level python based library (exposing ready to use workflows) and a CLI tool to control NSX for vSphere

PyNSXv can be used in two different ways, as a library by importing the files in the /library subdirectory into your code, or as a cli tool by calling `pynsxv`on the CLI after you installed pynsxv using pip on your system

**More extensive documentation will follow soon, including python and shell script examples**

# dependencies
PyNSXv has the following dependencies:
- pyvmomi (https://github.com/vmware/pyvmomi)
- nsxramlclient (https://github.com/vmware/nsxramlclient)
- tabulate (https://bitbucket.org/astanin/python-tabulate) 

Please check the installation instructions of these projects if you run into installation issues

# installing PyNSXv
PyNSXv can be installed using pip:
```shell
pip install pynsxv
```
