from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox


# --- Steganography Core Logic ---

def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def hide_data(image_path, secret_message):
    try:
        image = Image.open(image_path, 'r')
    except Exception as e:
        messagebox.showerror("Error", f"Could not open image: {e}")
        return None

    width, height = image.size
    pixel_map = image.load()

    # Add a unique delimiter to know where the message ends
    secret_message += "#####"
    binary_secret_message = text_to_binary(secret_message)
    
    data_index = 0
    message_length = len(binary_secret_message)

    # Check if the image is big enough
    if message_length > width * height * 3:
        messagebox.showerror("Error", "Message is too long for this image!")
        return None

    for y in range(height):
        for x in range(width):
            r, g, b = pixel_map[x, y][:3] # Get RGB values, ignore Alpha if present

            # Red channel
            if data_index < message_length:
                r_binary = list(format(r, '08b'))
                r_binary[-1] = binary_secret_message[data_index]
                new_r = int("".join(r_binary), 2)
                data_index += 1
            else: new_r = r

            # Green channel
            if data_index < message_length:
                g_binary = list(format(g, '08b'))
                g_binary[-1] = binary_secret_message[data_index]
                new_g = int("".join(g_binary), 2)
                data_index += 1
            else: new_g = g
            
            # Blue channel
            if data_index < message_length:
                b_binary = list(format(b, '08b'))
                b_binary[-1] = binary_secret_message[data_index]
                new_b = int("".join(b_binary), 2)
                data_index += 1
            else: new_b = b

            pixel_map[x, y] = (new_r, new_g, new_b)

            if data_index >= message_length: break
        if data_index >= message_length: break
            
    new_image_path = "encoded_" + image_path.split('/')[-1]
    image.save(new_image_path)
    return new_image_path

def unhide_data(image_path):
    try:
        image = Image.open(image_path, 'r')
    except Exception as e:
        messagebox.showerror("Error", f"Could not open image: {e}")
        return None

    width, height = image.size
    pixel_map = image.load()
    
    binary_data = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixel_map[x, y][:3]
            
            binary_data += format(r, '08b')[-1]
            binary_data += format(g, '08b')[-1]
            binary_data += format(b, '08b')[-1]
    
    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
    
    decoded_message = ""
    for byte in all_bytes:
        decoded_message += chr(int(byte, 2))
        if decoded_message[-5:] == "#####":
            return decoded_message[:-5]
            
    return None # If delimiter not found

# --- GUI Setup ---
class StegApp:
    def __init__(self, root):
        self.root = root
        self.root.title("KDU Steganography Tool")
        self.root.geometry("600x450") # Window size
        self.root.config(bg="#2C3E50") # Background color

        # --- Widgets ---
        title_label = tk.Label(root, text="Hide Your Secret Message", font=("Arial", 20, "bold"), bg="#2C3E50", fg="#ECF0F1")
        title_label.pack(pady=10)

        # Text area for the message
        self.message_text = tk.Text(root, height=8, width=60, bg="#34495E", fg="#ECF0F1", insertbackground="white")
        self.message_text.pack(pady=10)

        # Frame for buttons
        button_frame = tk.Frame(root, bg="#2C3E50")
        button_frame.pack(pady=20)

        # Buttons
        select_image_btn = tk.Button(button_frame, text="Select Image", command=self.select_image_file, bg="#1ABC9C", fg="white", font=("Arial", 12))
        select_image_btn.grid(row=0, column=0, padx=10)

        hide_btn = tk.Button(button_frame, text="Hide Data", command=self.encode_message, bg="#3498DB", fg="white", font=("Arial", 12))
        hide_btn.grid(row=0, column=1, padx=10)

        unhide_btn = tk.Button(button_frame, text="Reveal Data", command=self.decode_message, bg="#E74C3C", fg="white", font=("Arial", 12))
        unhide_btn.grid(row=0, column=2, padx=10)

        # Label to show selected file path
        self.file_path_label = tk.Label(root, text="No image selected", bg="#2C3E50", fg="#BDC3C7")
        self.file_path_label.pack(pady=5)
        
        # Variable to store file path
        self.image_path = ""

    # --- Button Functions (Will be filled later) ---
    def select_image_file(self):
        # This will open a file dialog
        self.image_path = filedialog.askopenfilename(
            initialdir="/", 
            title="Select an Image",
            filetypes=(("PNG files", "*.png"), ("All files", "*.*"))
        )
        if self.image_path:
            self.file_path_label.config(text=self.image_path)
        else:
            self.file_path_label.config(text="No image selected")

    def encode_message(self):
        messagebox.showinfo("Info", "Encode function will be here!")

    def decode_message(self):
        messagebox.showinfo("Info", "Decode function will be here!")

# --- Main ---
if __name__ == "__main__":
    root = tk.Tk()
    app = StegApp(root)
    root.mainloop()