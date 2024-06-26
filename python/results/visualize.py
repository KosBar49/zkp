import glob
from datetime import datetime
import matplotlib.pyplot as plt

HASH_TYPE = 'md5'
DATE = datetime.now().strftime('%Y-%m-%d %H%M%S')

# Read the file and parse the test names and their runtimes
for filename in glob.glob('results_*.txt'):
    print(filename)
    interactive_tests = {}
    ecc_tests = {}
    other_tests = {}
    with open(filename, 'r') as file:
        
        for line in file:
            # Separate the test name and runtime, assuming the format is consistent
            test_name, runtime_str = line.strip().split(': ')
            # Convert runtime to a float and remove the word 'miliseconds'
            runtime = float(runtime_str.split()[0])
            test_name = test_name.replace('test_', '')
            # Categorize the test based on its name
            if 'interactive' in test_name:
                test_name = test_name.replace('_interactive', '')
                interactive_tests[test_name] = runtime
            elif 'ecc' in test_name:
                test_name = test_name.replace('_ecc', '')
                ecc_tests[test_name] = runtime
            elif HASH_TYPE in test_name:
                other_tests[test_name] = runtime

    # Define a function for plotting a single category
    def plot_category(ax, category, title, color):
        ax.barh(list(category.keys()), list(category.values()), color=color)
        ax.set_title(title)
        ax.invert_yaxis()  # Invert axis to have the highest bar at the top
        ax.set_xlabel('Runtime (milliseconds)')
        ax.grid(True)

    # Create figure and axes for subplots
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))  # 1 row, 3 columns

    # Plot each category in its own subplot
    plot_category(axes[0], interactive_tests, 'Interactive Tests', 'lightgreen')
    plot_category(axes[1], ecc_tests, 'ECC Tests', 'lightcoral')
    plot_category(axes[2], other_tests, f'Non-Inter. Tests {HASH_TYPE}', 'lightblue')

    # Improve layout to prevent overlap
    plt.tight_layout()
    name = filename.replace(f'results_', '').replace('.txt','')+'.png'
    plt.savefig(name)