def main():
    hello('world')
    goodbye('world')
def hello(name):
    print(f'hello,{name}')
    
def multiply(num):
    return num*num

if __name__=='__main__':
    main()
    num= int(input('Enter number to be squared: '))
    sqr= multiply(num)
    print(sqr)
    
def goodbye(name):
    print(f'goodbye,{name}')