def calculate_bill(price, quantity, discount):
    subtotal = price * quantity
    final_price = subtotal * (1 - discount / 100)
    return final_price


price = 500
quantity = 2
discount = 50

bill = calculate_bill(price, quantity, discount)

print("Final bill:", bill)