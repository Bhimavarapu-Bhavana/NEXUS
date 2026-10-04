# Shop project file for NEXUS workspace tests
# A simple program for managing a product inventory and calculating totals.

def calculate_total(prices):
    """Calculate the total from a list of price values."""
    total = 0
    for price in prices:
        total += price
    return total

def add_product(inventory, name, price):
    """Add a product to the inventory dictionary."""
    inventory[name] = price
    return inventory

def get_cheapest_product(inventory):
    """Return the name of the cheapest product in the inventory."""
    if not inventory:
        return None
    return min(inventory, key=inventory.get)

# Example usage
if __name__ == "__main__":
    prices = [10.50, 20.00, 5.75, 15.25]
    print(f"Total: ${calculate_total(prices):.2f}")
    
    inventory = {}
    add_product(inventory, "widget", 15.00)
    add_product(inventory, "gadget", 25.00)
    add_product(inventory, "doohickey", 8.50)
    
    print(f"Inventory: {inventory}")
    print(f"Total: ${calculate_total(list(inventory.values())):.2f}")
    print(f"Cheapest product: {get_cheapest_product(inventory)}")