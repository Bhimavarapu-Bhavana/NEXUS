# Demo Python file for Phase 18 end-to-end tests
# Used with workspace_inspector and runtime_inspector tools
def calculate_factorial(n):
    """Calculate the factorial of a non-negative integer."""
    if n < 0:
        raise ValueError("Factorial is not defined for negative numbers")
    result = 1
    for i in range(1, n + 1):
        result *= i
    return result

# Main execution
if __name__ == "__main__":
    import sys
    try:
        n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
        if n < 0:
            raise ValueError("Factorial is not defined for negative numbers")
        result = calculate_factorial(n)
        print(f"Factorial of {n} is {result}")
    except (ValueError, IndexError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    
# Additional functions
def get_positive_integer(prompt):
    """Get a positive integer from user input."""
    while True:
        try:
            value = int(input(prompt))
            if value > 0:
                return value
            print("Please enter a positive integer.")
        except ValueError:
            print("Invalid input. Please enter a valid integer.")