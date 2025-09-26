import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import wave
import os

# --- Global App Settings ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

# -------------------------------------------------------------------
# --- Encryption Logic (Reusable for both Image and Audio) ---
# -------------------------------------------------------------------
def generate_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_message(message: str, password: str) -> bytes:
    salt = b'kdu_steg_salt_v2'
    key = generate_key_from_password(password, salt)
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(encrypted_message: bytes, password: str) -> str | None:
    salt = b'kdu_steg_salt_v2'
    key = generate_key_from_password(password, salt)
    f = Fernet(key)
    try:
        return f.decrypt(encrypted_message).decode()
    except Exception:
        return None

# -------------------------------------------------------------------
# --- Core Steganography Logic ---
# -------------------------------------------------------------------
def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

# --- IMAGE LOGIC ---
def hide_data_in_image(image_path, secret_message, password):
    try:
        image = Image.open(image_path, 'r')
    except Exception as e:
        messagebox.showerror("Error", f"Could not open image: {e}"); return None

    encrypted_message_bytes = encrypt_message(secret_message, password)
    secret_to_hide = base64.urlsafe_b64encode(encrypted_message_bytes).decode('utf-8')
    secret_to_hide += "#####" # Delimiter
    binary_secret_message = text_to_binary(secret_to_hide)
    
    capacity = image.width * image.height * 3
    if len(binary_secret_message) > capacity:
        messagebox.showerror("Error", "Message is too large for this image!"); return None

    new_image = image.copy()
    pixel_map = new_image.load()
    data_index = 0
    for y in range(image.height):
        for x in range(image.width):
            r, g, b = pixel_map[x, y][:3]
            if data_index < len(binary_secret_message): r = int(format(r, '08b')[:-1] + binary_secret_message[data_index], 2); data_index += 1
            if data_index < len(binary_secret_message): g = int(format(g, '08b')[:-1] + binary_secret_message[data_index], 2); data_index += 1
            if data_index < len(binary_secret_message): b = int(format(b, '08b')[:-1] + binary_secret_message[data_index], 2); data_index += 1
            pixel_map[x, y] = (r, g, b)
            if data_index >= len(binary_secret_message):
                new_image_path = "encoded_" + os.path.basename(image_path)
                new_image.save(new_image_path); return new_image_path
    return None

def unhide_data_from_image(image_path, password):
    # This logic remains largely the same but needs to be called correctly
    try:
        image = Image.open(image_path, 'r')
        pixel_map = image.load()
        binary_data = ""
        for y in range(image.height):
            for x in range(image.width):
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
                    hidden_data = decoded_string[:-5]; break
        else: return None

        encrypted_message_bytes = base64.urlsafe_b64decode(hidden_data)
        return decrypt_message(encrypted_message_bytes, password)
    except Exception:
        return None

# --- AUDIO LOGIC (WAV files) ---
def hide_data_in_audio(audio_path, secret_message, password):
    try:
        audio = wave.open(audio_path, 'rb')
        frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))
    except Exception as e:
        messagebox.showerror("Error", f"Could not open WAV file: {e}"); return None

    encrypted_message_bytes = encrypt_message(secret_message, password)
    secret_to_hide = base64.urlsafe_b64encode(encrypted_message_bytes).decode('utf-8')
    secret_to_hide += "#####"
    binary_secret_message = text_to_binary(secret_to_hide)

    capacity = len(frame_bytes) * 8
    if len(binary_secret_message) > capacity:
        messagebox.showerror("Error", "Message is too large for this audio file!"); return None

    for i in range(len(binary_secret_message)):
        frame_bytes[i] = (frame_bytes[i] & 254) | int(binary_secret_message[i])

    new_audio_path = "encoded_" + os.path.basename(audio_path)
    with wave.open(new_audio_path, 'wb') as fd:
        fd.setparams(audio.getparams())
        fd.writeframes(bytes(frame_bytes))
    audio.close()
    return new_audio_path

def unhide_data_from_audio(audio_path, password):
    try:
        audio = wave.open(audio_path, 'rb')
        frame_bytes = bytearray(list(audio.readframes(audio.getnframes())))
        audio.close()
        
        extracted_bits = [str(frame_bytes[i] & 1) for i in range(len(frame_bytes))]
        binary_data = "".join(extracted_bits)
        
        all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
        decoded_string = ""
        for byte in all_bytes:
            if len(byte) == 8:
                decoded_string += chr(int(byte, 2))
                if decoded_string.endswith("#####"):
                    hidden_data = decoded_string[:-5]; break
        else: return None
        
        encrypted_message_bytes = base64.urlsafe_b64decode(hidden_data)
        return decrypt_message(encrypted_message_bytes, password)
    except Exception:
        return None

# -------------------------------------------------------------------
# --- GUI Application ---
# -------------------------------------------------------------------
class StegApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("KDU Advanced Steganography Tool")
        self.geometry("750x600")
        self.resizable(False, False)

        # --- Instance variables ---
        self.image_path = ""
        self.audio_path = ""
        self.image_capacity = 0
        self.audio_capacity = 0

        # --- Main Tab View ---
        self.tab_view = ctk.CTkTabview(self, width=700, height=550)
        self.tab_view.pack(padx=20, pady=20)
        self.image_tab = self.tab_view.add("Image Steganography")
        self.audio_tab = self.tab_view.add("Audio Steganography (.wav)")
        
        self.create_image_widgets()
        self.create_audio_widgets()

    def create_shared_widgets(self, parent_tab):
        """Creates widgets common to both tabs."""
        message_text = ctk.CTkTextbox(parent_tab, height=150, width=600, corner_radius=8)
        password_entry = ctk.CTkEntry(parent_tab, placeholder_text="Enter Password for Encryption", show="*", width=300)
        capacity_label = ctk.CTkLabel(parent_tab, text="Capacity: N/A", text_color="gray")
        return message_text, password_entry, capacity_label

    def create_image_widgets(self):
        # Widgets
        self.image_message_text, self.image_password_entry, self.image_capacity_label = self.create_shared_widgets(self.image_tab)
        
        # Layout
        title = ctk.CTkLabel(self.image_tab, text="Hide Secrets in Images", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=(10, 20))
        self.image_message_text.pack(pady=10, padx=20)
        self.image_password_entry.pack(pady=(10, 20))
        
        btn_frame = ctk.CTkFrame(self.image_tab, fg_color="transparent")
        btn_frame.pack(pady=10)
        
        ctk.CTkButton(btn_frame, text="Select Image (.png)", command=self.select_image_file).grid(row=0, column=0, padx=10)
        ctk.CTkButton(btn_frame, text="Hide Data", command=self.encode_image_message).grid(row=0, column=1, padx=10)
        ctk.CTkButton(btn_frame, text="Reveal Data", command=self.decode_image_message, fg_color="#D32F2F", hover_color="#B71C1C").grid(row=0, column=2, padx=10)

        self.image_file_label = ctk.CTkLabel(self.image_tab, text="No image selected", text_color="gray")
        self.image_file_label.pack(pady=5)
        self.image_capacity_label.pack(pady=5)

        # Bind events for capacity checker
        self.image_message_text.bind("<KeyRelease>", self.update_capacity_label)
        self.image_password_entry.bind("<KeyRelease>", self.update_capacity_label)

    def create_audio_widgets(self):
        self.audio_message_text, self.audio_password_entry, self.audio_capacity_label = self.create_shared_widgets(self.audio_tab)
        
        title = ctk.CTkLabel(self.audio_tab, text="Hide Secrets in Audio", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=(10, 20))
        self.audio_message_text.pack(pady=10, padx=20)
        self.audio_password_entry.pack(pady=(10, 20))

        btn_frame = ctk.CTkFrame(self.audio_tab, fg_color="transparent")
        btn_frame.pack(pady=10)
        
        ctk.CTkButton(btn_frame, text="Select Audio (.wav)", command=self.select_audio_file).grid(row=0, column=0, padx=10)
        ctk.CTkButton(btn_frame, text="Hide Data", command=self.encode_audio_message).grid(row=0, column=1, padx=10)
        ctk.CTkButton(btn_frame, text="Reveal Data", command=self.decode_audio_message, fg_color="#D32F2F", hover_color="#B71C1C").grid(row=0, column=2, padx=10)

        self.audio_file_label = ctk.CTkLabel(self.audio_tab, text="No audio selected", text_color="gray")
        self.audio_file_label.pack(pady=5)
        self.audio_capacity_label.pack(pady=5)
        
        self.audio_message_text.bind("<KeyRelease>", self.update_capacity_label)
        self.audio_password_entry.bind("<KeyRelease>", self.update_capacity_label)

    def get_current_data_size(self, message, password):
        if not message or not password: return 0
        encrypted = encrypt_message(message, password)
        b64_encoded = base64.urlsafe_b64encode(encrypted)
        return len(b64_encoded) * 8 # Size in bits

    def update_capacity_label(self, event=None):
        active_tab = self.tab_view.get()
        if active_tab == "Image Steganography" and self.image_capacity > 0:
            message = self.image_message_text.get("1.0", "end-1c")
            password = self.image_password_entry.get()
            used_bits = self.get_current_data_size(message, password)
            self.image_capacity_label.configure(text=f"Capacity: {used_bits:,} / {self.image_capacity:,} bits used")
        elif active_tab == "Audio Steganography (.wav)" and self.audio_capacity > 0:
            message = self.audio_message_text.get("1.0", "end-1c")
            password = self.audio_password_entry.get()
            used_bits = self.get_current_data_size(message, password)
            self.audio_capacity_label.configure(text=f"Capacity: {used_bits:,} / {self.audio_capacity:,} bits used")

    # --- File Selection Methods ---
    def select_image_file(self):
        self.image_path = filedialog.askopenfilename(title="Select PNG Image", filetypes=(("PNG files", "*.png"),))
        if self.image_path:
            self.image_file_label.configure(text=f"Selected: {os.path.basename(self.image_path)}")
            with Image.open(self.image_path) as img:
                self.image_capacity = img.width * img.height * 3
            self.update_capacity_label()
        
    def select_audio_file(self):
        self.audio_path = filedialog.askopenfilename(title="Select WAV Audio", filetypes=(("WAV files", "*.wav"),))
        if self.audio_path:
            self.audio_file_label.configure(text=f"Selected: {os.path.basename(self.audio_path)}")
            with wave.open(self.audio_path, 'rb') as wav:
                self.audio_capacity = wav.getnframes() * wav.getnchannels() * 8
            self.update_capacity_label()

    # --- Encoding/Decoding Methods ---
    def encode_image_message(self):
        if not self.image_path: messagebox.showerror("Error", "Please select an image!"); return
        message = self.image_message_text.get("1.0", "end-1c")
        password = self.image_password_entry.get()
        if not message or not password: messagebox.showerror("Error", "Message and Password are required!"); return
        
        new_file = hide_data_in_image(self.image_path, message, password)
        if new_file:
            messagebox.showinfo("Success", f"Data hidden in {os.path.basename(new_file)}")

    def decode_image_message(self):
        if not self.image_path: messagebox.showerror("Error", "Please select an image!"); return
        password = self.image_password_entry.get()
        if not password: messagebox.showerror("Error", "Password is required!"); return
        
        secret = unhide_data_from_image(self.image_path, password)
        if secret:
            self.image_message_text.delete("1.0", "end")
            self.image_message_text.insert("1.0", secret)
            messagebox.showinfo("Success", "Message Revealed!")
        else:
            messagebox.showerror("Error", "Failed to reveal message. Check password or file.")

    def encode_audio_message(self):
        if not self.audio_path: messagebox.showerror("Error", "Please select an audio file!"); return
        message = self.audio_message_text.get("1.0", "end-1c")
        password = self.audio_password_entry.get()
        if not message or not password: messagebox.showerror("Error", "Message and Password are required!"); return
        
        new_file = hide_data_in_audio(self.audio_path, message, password)
        if new_file:
            messagebox.showinfo("Success", f"Data hidden in {os.path.basename(new_file)}")

    def decode_audio_message(self):
        if not self.audio_path: messagebox.showerror("Error", "Please select an audio file!"); return
        password = self.audio_password_entry.get()
        if not password: messagebox.showerror("Error", "Password is required!"); return
        
        secret = unhide_data_from_audio(self.audio_path, password)
        if secret:
            self.audio_message_text.delete("1.0", "end")
            self.audio_message_text.insert("1.0", secret)
            messagebox.showinfo("Success", "Message Revealed!")
        else:
            messagebox.showerror("Error", "Failed to reveal message. Check password or file.")


if __name__ == "__main__":
    app = StegApp()
    app.mainloop()