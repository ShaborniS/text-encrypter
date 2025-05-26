def main():
    x=int(input('whats x? '))
    if is_even(x):
        print('even')
    else:
        print('odd')
def is_even(n):
    return (n % 2 == 0)
main() 
def house():
    name=input('whats your name? ')
    match name:
        case "shaborni"|"garima"|"sita":
            print('indian')
        case _:
            print("idk")
house()
print('meow '*3) 