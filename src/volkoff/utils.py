import os
import time
import zipfile


from rich.prompt import Prompt

from volkoff.tui import list_current_files, format_directory_listing


def handle_files_folder(console, current_dir):
    while True:
        files, dirs, current_path = list_current_files(current_dir)
        listing = format_directory_listing(files, dirs, current_path)
        console.print(listing)

        if not files and not dirs:
            console.print("\n[bold red]No files found in this directory![/]")
            time.sleep(2)
            break

        try:
            file_index = int(Prompt.ask("\nEnter number", default="1"))

            # Handle parent directory
            if file_index == 0 and current_path != current_path.root:
                current_dir = current_dir.parent
                continue

            # Handle directory selection
            if file_index <= len(dirs):
                current_dir = dirs[file_index - 1]
                continue

            # Handle file selection
            if file_index <= len(dirs) + len(files):
                file_path = files[file_index - len(dirs) - 1]
                break

            raise ValueError("Invalid selection!")

        except ValueError as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            time.sleep(1)
            continue
    return file_path


def handle_folder(console, current_dir):
    """
    This function displays directories for the user to pick.
    Once the user picks a directory, it prompts the user to either compress it
    or navigate inside it to pick another directory.
    """
    while True:
        # Get the list of files and directories in the current directory
        files, dirs, current_path = list_current_files(current_dir)

        # Format and display the directory listing
        listing = format_directory_listing(files, dirs, current_path)
        console.print(listing)

        # If no directories are found, exit the loop
        if not dirs:
            console.print("\n[bold red]No directories found in this directory![/]")
            time.sleep(2)
            break

        try:
            # Ask the user to select a directory by entering a number
            dir_index = int(
                Prompt.ask("\nEnter number to select a directory", default="1")
            )
            if dir_index <= len(dirs):
                dir_path = dirs[dir_index - 1]
                break  # Exit loop once a valid directory is selected
            raise ValueError("Invalid selection!")

        except ValueError as e:
            console.print(f"[bold red]Error:[/] {str(e)}")
            time.sleep(1)
            continue

    # Once a directory is selected, ask the user what action to take
    while True:
        action = Prompt.ask(
            "[bold blue]Do you want to compress this directory (c) or navigate (n) to a subdirectory? (Enter 'c' or 'n')",
            choices=["c", "n"],
            default="c",
        )

        if action == "c":
            # Path to the directory to compress
            dir_to_compress = os.path.join(current_dir, dir_path)

            # Create a zip file path (same directory, with .zip extension)
            zip_file_path = os.path.join(current_dir, f"{dir_path}.zip")

            # Compress the directory into a zip file, without traversing into subdirectories
            try:
                with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                    # List files in the root of the selected directory, without walking into subdirectories
                    for file in os.listdir(dir_to_compress):
                        file_path = os.path.join(dir_to_compress, file)

                        # Only add files (not directories) to the zip file
                        if os.path.isfile(file_path):
                            arcname = os.path.relpath(file_path, start=dir_to_compress)
                            zipf.write(file_path, arcname)

                console.print(
                    f"\n[bold green]Directory '{dir_path}' successfully compressed to '{zip_file_path}'[/]"
                )

            except Exception as e:
                console.print(f"[bold red]Error during compression:[/] {str(e)}")

            return zip_file_path  # Return the path of the compressed file

        elif action == "n":
            # If the user chooses to navigate, update the current directory and continue the loop
            current_dir = os.path.join(current_dir, dir_path)
            console.print(f"\nNavigating to {current_dir}")
            break  # Break out of the inner loop to allow for further selection or compression
