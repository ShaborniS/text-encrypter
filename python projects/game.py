from random import randint
true_num = randint(1, 100)

while True:
    num = int(input('Enter your Guess! (between 1 to 100) or 0 to stop: '))
    
    if num == 0:
        print('Game over!')
        break
    elif num == true_num:
        print('You are right!')
        break
    elif num > true_num:
        print('Your guess is high, try again!')
    else:
        print('Your guess is low, try again!')