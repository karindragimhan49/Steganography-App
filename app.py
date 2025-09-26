# Step 1: Import necessary libraries
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image

# -------------------------------------------------------------------
# --- Steganography Core Logic (The Brain of the Application) ---
# -------------------------------------------------------------------

def text_to_binary(text):
    """Converts a string of text into a binary string."""
    return ''.join(format(ord(char), '08b') for char in text)

def hide_data(image_path, secret_message):
    """Hides a secret message within an image file."""
    try:
        image = Image.open(image_path, 'r')
    except Exception as e:
        messagebox.showerror("Error", f"Could not open image file: {e}")
        return None

    # We need a copy to modify
    new_image = image.copy()
    width, height = new_image.size
    pixel_map = new_image.load()

    # Add a unique delimiter to signal the end of the message
    secret_message += "#####"
    binary_secret_message = text_to_binary(secret_message)
    
    data_index = 0
    message_length = len(binary_secret_message)

    # Check if the image has enough space to hold the message
    if message_length > width * height * 3:
        messagebox.showerror("Error", "Message is too large for this image. Please choose a larger image or a shorter message.")
        return None

    # Iterate over each pixel to hide data
    for y in range(height):
        for x in range(width):
            # Get the RGB values of the pixel
            r, g, b = pixel_map[x, y][:3]

            # Modify the Red channel's LSB
            if data_index < message_length:
                r_binary = list(format(r, '08b'))
                r_binary[-1] = binary_secret_message[data_index]
                new_r = int("".join(r_binary), 2)
                data_index += 1
            else:
                new_r = r

            # Modify the Green channel's LSB
            if data_index < message_length:
                g_binary = list(format(g, '08b'))
                g_binary[-1] = binary_secret_message[data_index]
                new_g = int("".join(g_binary), 2)
                data_index += 1
            else:
                new_g = g
            
            # Modify the Blue channel's LSB
            if data_index < message_length:
                b_binary = list(format(b, '08b'))
                b_binary[-1] = binary_secret_message[data_index]
                new_b = int("".join(b_binary), 2)
                data_index += 1
            else:
                new_b = b

            # Update the pixel with new RGB values
            pixel_map[x, y] = (new_r, new_g, new_b)

            # If the entire message is hidden, stop processing
            if data_index >= message_length:
                # Save the new image
                # Example: if original is 'cat.png', new one will be 'encoded_cat.png'
                original_filename = image_path.split('/')[-1]
                new_image_path = "encoded_" + original_filename
                new_image.save(new_image_path)
                return new_image_path
    return None # Should not be reached if logic is correct

def unhide_data(image_path):
    """Reveals a hidden message from an image file."""
    try:
        image = Image.open(image_path, 'r')
    except Exception as e:
        messagebox.showerror("Error", f"Could not open image file: {e}")
        return None

    width, height = image.size
    pixel_map = image.load()
    
    binary_data = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixel_map[x, y][:3]
            
            # Extract the LSB from each color channel
            binary_data += format(r, '08b')[-1]
            binary_data += format(g, '08b')[-1]
            binary_data += format(b, '08b')[-1]
    
    # Convert binary string back to text
    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
    
    decoded_message = ""
    for byte in all_bytes:
        # Check for potential non-ASCII characters that might cause errors
        if len(byte) == 8:
            try:
                decoded_message += chr(int(byte, 2))
                # Check if the delimiter is found
                if decoded_message[-5:] == "#####":
                    return decoded_message[:-5] # Return message without the delimiter
            except ValueError:
                # This can happen if the extracted bits don't form a valid character
                pass
            
    return None # Return None if no message/delimiter is found


# -------------------------------------------------------------------
# --- GUI Setup (The UI you already built, now connected to logic) ---
# -------------------------------------------------------------------

class StegApp:
    def __init__(self, root):
        self.root = root
        self.root.title("KDU Steganography Tool")
        self.root.geometry("600x450")
        self.root.config(bg="#2C3E50")
        self.root.resizable(False, False) # Make window not resizable

        self.image_path = "" # Variable to store the selected image path

        # --- Widgets ---
        title_label = tk.Label(root, text="Hide Your Secret Message", font=("Arial", 20, "bold"), bg="#2C3E50", fg="#ECF0F1")
        title_label.pack(pady=10)

        # Text area for the message
        self.message_text = tk.Text(root, height=8, width=60, bg="#34495E", fg="#ECF0F1", insertbackground="white", relief="flat")
        self.message_text.pack(pady=10)

        # Frame for buttons
        button_frame = tk.Frame(root, bg="#2C3E50")
        button_frame.pack(pady=20)

        # Buttons
        select_image_btn = tk.Button(button_frame, text="Select Image", command=self.select_image_file, bg="#1ABC9C", fg="white", font=("Arial", 12), relief="flat")
        select_image_btn.grid(row=0, column=0, padx=10)

        hide_btn = tk.Button(button_frame, text="Hide Data", command=self.encode_message, bg="#3498DB", fg="white", font=("Arial", 12), relief="flat")
        hide_btn.grid(row=0, column=1, padx=10)

        unhide_btn = tk.Button(button_frame, text="Reveal Data", command=self.decode_message, bg="#E74C3C", fg="white", font=("Arial", 12), relief="flat")
        unhide_btn.grid(row=0, column=2, padx=10)

        # Label to show selected file path
        self.file_path_label = tk.Label(root, text="No image selected", bg="#2C3E50", fg="#BDC3C7")
        self.file_path_label.pack(pady=5)

    # --- Button Command Functions ---

    def select_image_file(self):
        """Opens a file dialog to select an image."""
        self.image_path = filedialog.askopenfilename(
            title="Select an Image",
            filetypes=(("PNG files", "*.png"), ("All files", "*.*"))
        )
        if self.image_path:
            filename = self.image_path.split('/')[-1]
            self.file_path_label.config(text=f"Selected: {filename}")
        else:
            self.file_path_label.config(text="No image selected")

    def encode_message(self):
        """Handles the 'Hide Data' button click."""
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return
        
        secret = self.message_text.get("1.0", "end-1c")
        if not secret:
            messagebox.showerror("Error", "Please enter a secret message to hide!")
            return

        # Call the core logic function
        new_image = hide_data(self.image_path, secret)
        
        if new_image:
            messagebox.showinfo("Success", f"Message hidden successfully!\nSaved as: {new_image}")
            self.message_text.delete("1.0", "end") # Clear the text box after encoding

    def decode_message(self):
        """Handles the 'Reveal Data' button click."""
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image file to reveal data from!")
            return

        # Call the core logic function
        revealed_message = unhide_data(self.image_path)
        
        if revealed_message:
            self.message_text.delete("1.0", "end") # Clear text box
            self.message_text.insert("1.0", revealed_message) # Show revealed message in text box
            messagebox.showinfo("Success", "Message revealed successfully!")
        else:
            messagebox.showerror("Error", "No hidden message found or the image is corrupted.")

# -------------------------------------------------------------
# --- Main entry point to run the application ---
# -------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = StegApp(root)
    root.mainloop()