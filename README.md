# dstar-dd

# Problems:
- TypeError: 'numpy.float64' object cannot be interpreted as an index

Solution: There is some incompatibility between commpy and newer versions
if numy.  Until this is fixed in commpy, a workaround is using an older
version of numpy

sudo pip install -U numpy==1.11.0.

(This will turn the error into a warning)


