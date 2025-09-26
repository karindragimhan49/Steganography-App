import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Global Settings for the App ---
ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"


# -------------------------------------------------------------------
# --- Encryption & Steganography Core Logic (The New Brain) ---
# -------------------------------------------------------------------

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """Generates a secure encryption key from a user's password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_message(message: str, password: str) -> bytes:
    """Encrypts a message using the generated key."""
    salt = b'kdu_steg_salt_'  # A fixed salt. For production, generate and save a random salt.
    key = generate_key_from_password(password, salt)
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message: bytes, password: str) -> str | None:
    """Decrypts a message using the provided key."""
    salt = b'kdu_steg_salt_'
    key = generate_key_from_password(password, salt)
    f = Fernet(key)
    try:
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode()
    except Exception:
        # This will fail if the password is wrong
        return None

def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def hide_data(image_path, secret_message, password):
    try:
        image = Image.open(image_path, 'r')
    except Exception as e:
        messagebox.showerror("Error", f"Could not open image: {e}")
        return None

    # 1. Encrypt the message first!
    encrypted_message_bytes = encrypt_message(secret_message, password)
    # Convert bytes to a string that can be hidden (Base64 is good for this)
    secret_to_hide = base64.urlsafe_b64encode(encrypted_message_bytes).decode('utf-8')

    new_image = image.copy()
    width, height = new_image.size
    pixel_map = new_image.load()

    secret_to_hide += "#####" # Delimiter
    binary_secret_message = text_to_binary(secret_to_hide)
    
    data_index = 0
    message_length = len(binary_secret_message)

    if message_length > width * height * 3:
        messagebox.showerror("Error", "Message is too large for this image!")
        return None

    for y in range(height):
        for x in range(width):
            r, g, b = pixel_map[x, y][:3]
            # --- Hide logic (same as before) ---
            if data_index < message_length: r = int(format(r, '08b')[:-1] + binary_secret_message[data_index], 2); data_index += 1
            if data_index < message_length: g = int(format(g, '08b')[:-1] + binary_secret_message[data_index], 2); data_index += 1
            if data_index < message_length: b = int(format(b, '08b')[:-1] + binary_secret_message[data_index], 2); data_index += 1
            pixel_map[x, y] = (r, g, b)
            if data_index >= message_length:
                original_filename = image_path.split('/')[-1]
                new_image_path = "encrypted_" + original_filename
                new_image.save(new_image_path)
                return new_image_path
    return None

def unhide_data(image_path, password):
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
    
    decoded_string = ""
    for byte in all_bytes:
        if len(byte) == 8:
            decoded_string += chr(int(byte, 2))
            if decoded_string.endswith("#####"):
                hidden_data = decoded_string[:-5]
                break
    else: # If loop finishes without finding delimiter
        return None

    # 1. Decode from Base64
    try:
        encrypted_message_bytes = base64.urlsafe_b64decode(hidden_data)
    except:
        return None # Corrupted data

    # 2. Decrypt the message
    decrypted_message = decrypt_message(encrypted_message_bytes, password)
    return decrypted_message


# -------------------------------------------------------------------
# --- GUI Setup (The New Professional UI) ---
# -------------------------------------------------------------------

class StegApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("KDU Steganography Tool")
        self.geometry("600x550")
        self.resizable(False, False)

        self.image_path = ""

        # --- Main Frame ---
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        # --- Widgets ---
        title_label = ctk.CTkLabel(main_frame, text="Hide Your Secret Message", font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(10, 20))

        # Text area for the message
        self.message_text = ctk.CTkTextbox(main_frame, height=150, width=400, corner_radius=8)
        self.message_text.pack(pady=10, padx=10)
        
        # Password entry
        self.password_entry = ctk.CTkEntry(main_frame, placeholder_text="Enter Password for Encryption", show="*", width=300)
        self.password_entry.pack(pady=(10, 20))

        # Frame for buttons
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(pady=10)

        # Buttons
        select_image_btn = ctk.CTkButton(button_frame, text="Select Image", command=self.select_image_file, width=140, height=40, font=ctk.CTkFont(size=14, weight="bold"))
        select_image_btn.grid(row=0, column=0, padx=10)

        hide_btn = ctk.CTkButton(button_frame, text="Hide Data", command=self.encode_message, width=140, height=40, font=ctk.CTkFont(size=14, weight="bold"))
        hide_btn.grid(row=0, column=1, padx=10)

        unhide_btn = ctk.CTkButton(button_frame, text="Reveal Data", command=self.decode_message, fg_color="#D32F2F", hover_color="#B71C1C", width=140, height=40, font=ctk.CTkFont(size=14, weight="bold"))
        unhide_btn.grid(row=0, column=2, padx=10)

        # Label to show selected file path
        self.file_path_label = ctk.CTkLabel(main_frame, text="No image selected", text_color="gray")
        self.file_path_label.pack(pady=10)

    def select_image_file(self):
        self.image_path = filedialog.askopenfilename(title="Select an Image", filetypes=(("PNG files", "*.png"), ("All files", "*.*")))
        if self.image_path:
            self.file_path_label.configure(text=f"Selected: {self.image_path.split('/')[-1]}")
        else:
            self.file_path_label.configure(text="No image selected")

    def encode_message(self):
        if not self.image_path: messagebox.showerror("Error", "Please select an image first!"); return
        secret = self.message_text.get("1.0", "end-1c")
        password = self.password_entry.get()
        if not secret: messagebox.showerror("Error", "Please enter a secret message!"); return
        if not password: messagebox.showerror("Error", "Please enter a password for encryption!"); return

        new_image = hide_data(self.image_path, secret, password)
        if new_image:
            messagebox.showinfo("Success", f"Message encrypted and hidden!\nSaved as: {new_image}")
            self.message_text.delete("1.0", "end")
            self.password_entry.delete(0, 'end')

    def decode_message(self):
        if not self.image_path: messagebox.showerror("Error", "Please select an image to decode!"); return
        password = self.password_entry.get()
        if not password: messagebox.showerror("Error", "Please enter the password to decrypt!"); return

        revealed_message = unhide_data(self.image_path, password)
        if revealed_message:
            self.message_text.delete("1.0", "end")
            self.message_text.insert("1.0", revealed_message)
            messagebox.showinfo("Success", "Message revealed successfully!")
        else:
            messagebox.showerror("Error", "Failed to reveal message. Check if the password is correct or the image is corrupted.")

# --- Main entry point ---
if __name__ == "__main__":
    app = StegApp()
    app.mainloop()