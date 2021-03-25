# ArchRide


### Challenge Description

I have a long one planned. Buckle up!
Limit your character check to the printable range please :)

### Challenge file 

[surprise](Handout/suprise)

### Flag
```
inctf{x32_x64_ARM_MAC_powerPC_4rch_maz3_6745}
```

### Solution 

The challenge solution script has been added under Admin/Solution which is the intended solution. The unintended approach is that the header of the bzip can be used to bruteforce the input to each level and the binaries can be emulated and run in the various archs to get the flag.
  - Total no of levels: 120

Solution Script:

Script uses rzpipe to extract the checker values from the binary which are later used to bruteforce the values using z3.
 
[script.py](Admin/Solution/solver.py)
