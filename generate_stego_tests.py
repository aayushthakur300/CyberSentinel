from PIL import Image
from stegano import lsb
import os
import io

def create_base_images():
    print("[*] Creating dummy base images...")
    # Create a simple blue PNG
    img_png = Image.new('RGB', (150, 150), color = (0, 0, 255))
    img_png.save('base_blue.png')
    
    # Create a simple green JPG
    img_jpg = Image.new('RGB', (150, 150), color = (0, 255, 0))
    # JPG needs to be saved with some quality setting
    img_jpg.save('base_green.jpg', quality=95)

def generate_lsb_stego():
    """
    TEST 1: LSB Steganography (Works best on PNG)
    Hides a message inside the pixels themselves.
    """
    print("\n[1] Generating LSB Steganography Test Image (PNG)...")
    
    secret_message = "FLAG{LSB_stego_successfully_detected_by_CyberSentinel}"
    
    try:
        # Use stegano library to hide the message inside the base image
        secret_img = lsb.hide("base_blue.png", secret_message)
        output_filename = "test_stego_LSB_secret.png"
        secret_img.save(output_filename)
        print(f"[+] Created: {output_filename}")
        print("    -> Upload this file. The analyzer should find the 'FLAG{...}' message.")
    except Exception as e:
        print(f"[-] Error generating LSB image: {e}")

def generate_lazy_stego():
    """
    TEST 2: "Lazy" Appended Text Steganography (Works on JPG/any file)
    Just appends text to the end of the binary file after the image data terminator.
    """
    print("\n[2] Generating Appended Text Test Image (JPG)...")
    input_filename = "base_green.jpg"
    output_filename = "test_stego_lazy_append.jpg"

    try:
        # Read original image bytes
        with open(input_filename, "rb") as f:
            file_content = f.read()

        # The suspicious data to hide at the end
        hidden_data = b"\n\n--- BEGIN HIDDEN SECTION ---\n"
        hidden_data += b"Why are you looking down here?\n"
        hidden_data += b"password=super_secret_admin_pass\n"
        hidden_data += b"--- END HIDDEN SECTION ---"

        # Write original content + hidden data to new file
        with open(output_filename, "wb") as f:
            f.write(file_content)
            f.write(hidden_data)
            
        print(f"[+] Created: {output_filename}")
        print("    -> Upload this file. The analyzer should detect the 'password' string in raw bytes.")
        
    except Exception as e:
        print(f"[-] Error generating appended text image: {e}")

def cleanup():
    print("\n[*] Cleaning up temporary base images...")
    try:
        os.remove('base_blue.png')
        os.remove('base_green.jpg')
        print("[+] Cleanup complete.")
    except OSError:
        pass

if __name__ == "__main__":
    print("=== CyberSentinel Steganography Test Generator ===\n")
    create_base_images()
    generate_lsb_stego()
    generate_lazy_stego()
    cleanup()
    print("\n=== Generation Complete. Check your folder for the 'test_stego_*.png/jpg' files. ===")