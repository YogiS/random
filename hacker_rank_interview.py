# write a function which accepts one string argument and returns either True or False to indicate whether its argument is or is not a palindrome.
#!/usr/bin/env python2.7
import re

def is_palindrome(input):
    input=sanitize(input)
    if input == reverse(input):
        return True
    else:
        return False
        
def sanitize(input):
    input=input.lower()
    input=re.sub(r'[^0-9a-zA-Z]+', '', input)
    return input
    
def reverse(input):
    return input[::-1]


print(is_palindrome("mom"))
print(is_palindrome("noon"))
print(is_palindrome("a"))
print(is_palindrome("foo"))
print(is_palindrome("RaceCar"))
print(is_palindrome(" ab cba"))
print(is_palindrome("a,b?c;ba"))
