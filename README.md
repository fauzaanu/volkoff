# Volkoff

Volkoff helps you lock and unlock your files. It's like a safe for your computer files!

To get Volkoff, type this:
```bash
pip install volkoff
```

To start it, just type:
```bash
vk
```

## How It Works

When you lock a file:
1. Volkoff makes a special key just for you using strong AES-256 encryption
2. It puts your file in a special container that keeps:
   - The type of file (like .jpg or .pdf)
   - The file's contents
   - A unique number that makes each lock different
3. It locks everything up with your key
4. It gives you the key to save

When you want to unlock it:
1. You give Volkoff your key
2. It checks if the key is right
3. It opens the container and gets:
   - The original file type
   - Your file's contents
4. It puts your file back together, exactly like it was before

## What Makes It Safe

- Uses AES-256 encryption (the same kind banks use)
- Each file gets a fresh random number when locked
- The container keeps your file type and data together safely
- No one can change the locked file without the right key

Remember:
- Keep your key safe! Without it, you can't unlock your files
- Write down your key somewhere safe
- Test unlocking right after you lock something important
