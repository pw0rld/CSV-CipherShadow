# One-Shot Ciphertext Leakage

## Attack Steps

This section outlines the steps involved in the one-shot ciphertext leakage attack. The attack leverages CipherShadow leakage to reconstruct images from a training dataset.

### Directories and Files

- **`if_dir` Directory**: This folder contains the original image training set.

- **`of_dir` Directory**: This folder holds the images that have been reconstructed as a result of the attack.

- **`leak.bin` File**: This file contains the raw memory data collected from the one-shot dump of the original image training set.
- **`leakage-attack.py` File**: Code for image recovery and calculation of recovery success rate.

### Procedure
Run the following commands to execute the attack.

```bash
python leakage-attack.py
```


