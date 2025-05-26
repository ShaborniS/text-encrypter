import cowsay
import sys
if len(sys.argv)<2:
    print('too few arguments')
elif len(sys.argv)>2:
    print('too many arguments')
else:
    cowsay.kitty('hello, ' +sys.argv[1])
import statistics
print(statistics.mean([100,90]))
import random
colours= random.choice(['red','blue','white','black','orange','yellow'])
print('selected :', colours)