# Open the file in read mode
with open("html_injection.txt", "r") as file:
    # Read and print each line
    for line in file:
        print(line.strip())  # strip() removes trailing newline characters
