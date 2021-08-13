import sys
from Registry import Registry

reg = Registry.Registry("./artifacts/NTUSER.dat")

key = reg.open("SOFTWARE\\SimonTatham\\PuTTY\\Sessions")
#key = reg.open("SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions")

def print_key(key: Registry.RegistryKey):
    print(key.name())

    # for value in key.values():
    #     print("%s: %s" % (value.name(), value.value()))

    for s in key.subkeys():
        print(s.name())

    print("=========")

for value in key.values():
    print("%s: %s" % (value.name(), value.value()))

for s in key.subkeys():
    print_key(s)

# for value in [v for v in key.values() \
#                    if v.value_type() == Registry.RegSZ or \
#                       v.value_type() == Registry.RegExpandSZ]:
#     print("%s: %s" % (value.name(), value.value()))