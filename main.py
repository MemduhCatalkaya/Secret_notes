import tkinter
from PIL import ImageTk, Image
import base64
from tkinter import messagebox

fixing = 1


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


window = tkinter.Tk()
window.title("Secret Notes")
window.minsize(450, 800)

frame = tkinter.Frame(window, width=217, height=450)
frame.place(anchor='center', relx=0.5, y=250)
img = ImageTk.PhotoImage(Image.open("secret_information.png"))

img_label = tkinter.Label(frame, image=img)
img_label.place(anchor='center', relx=0.5, y=100)

title_label = tkinter.Label(text="Enter Your Title", font=("arial", 15, "bold"))
title_label.place(relx=0.5, y=250, anchor="center")

title_entry = tkinter.Entry()
title_entry.place(width=300, height=20, relx=0.5, anchor="center", y=280)

secret_label = tkinter.Label(text="Enter Your Secret", font=("arial", 15, "bold"))
secret_label.place(relx=0.5, y=310, anchor="center")

text_entry = tkinter.Text()
text_entry.place(width=350, height=330, relx=0.5, anchor="center", y=490)

master_key_label = tkinter.Label(text="Enter Master Key", font=("arial", 15, "bold"))
master_key_label.place(relx=0.5, y=675, anchor="center")

master_key_entry = tkinter.Entry()
master_key_entry.place(width=300, height=20, relx=0.5, anchor="center", y=700)


def save_and_encrypt():

    global fixing
    try:
        fixing = 1 / (len(title_entry.get()) * len(text_entry.get("1.0", "end")) * len(master_key_entry.get()))
        encryptedfile = encode(master_key_entry.get(), text_entry.get("1.0", "end"))
        with open("file.txt", mode="a") as file:
            file.write(f"{title_entry.get()}\n\n{encryptedfile}\n\n")
        title_entry.delete(0, "end")
        text_entry.delete("1.0", "end")
        master_key_entry.delete(0, "end")
    except ZeroDivisionError:
        messagebox.showinfo("Missing Information!", "Please enter all information!")


def decrypt():
    global fixing
    try:
        fixing = 1 / (len(text_entry.get(1.0, "end")) * len(master_key_entry.get()))
        decrypted_file = decode(master_key_entry.get(), text_entry.get("1.0", "end"))
        text_entry.delete("1.0", "end")
        text_entry.insert("end", decrypted_file)
    except ZeroDivisionError:
        messagebox.showinfo("Missing Information!", "Please enter all information!")
    except:
        messagebox.showinfo("Wrong Information!", "Please enter decrypted file code correctly!")


save_and_encrypt_button = tkinter.Button(width=15, text="Save and Encrypt", command=save_and_encrypt)
save_and_encrypt_button.place(relx=0.5, y=730, anchor="center")

decrypt_button = tkinter.Button(width=10, text="Decrypt", command=decrypt)
decrypt_button.place(relx=0.5, y=760, anchor="center")


window.mainloop()
