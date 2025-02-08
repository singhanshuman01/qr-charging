import qrcode

# URL for the login page (replace with your actual local server address)
login_url = "http://localhost:5000/login"

# Generate the QR code
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(login_url)
qr.make(fit=True)

# Create an image of the QR code
qr_img = qr.make_image(fill_color="black", back_color="white")

# Save the QR code as an image file
qr_img.save("login_qr_code.png")

print("QR code generated and saved as 'login_qr_code.png'.")
