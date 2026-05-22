# Ascon-XOF128 Attacks

This folder contains implementations and data for MitM trail search and preimage attacks on **Ascon-XOF128**, including re-search and visualization.

## Subfolders

- **`search_result/`**  
  Stores results from the **red and blue bits** search stage and the **long-running** search stage.

- **`final_result/`**  
  Stores results after the **re-search** phase and includes code for plotting/visualization.

- **`tex/`**  
  LaTeX figure code used for drawing the results.

## Files

### 3-round preimage attack
- **`Ascon_XOF_3_preimage.py`**  
  Search code for preimage attack on 3-round Ascon-XOF128

- **`Ascon_XOF_3_preimage1.py`**  
  Alternative search code for preimage attack on 3-round Ascon-XOF128

- **`Ascon_XOF_re_search3.py`**  
  Re-search stage code for preimage attack on 3-round Ascon-XOF128

### 4-round preimage attack
- **`Ascon_XOF_4_preimage.py`**  
  Search code for preimage attack on 4-round Ascon-XOF128

- **`Ascon_XOF_4_preimage12.py`**  
  Alternative search code for preimage attack on 4-round Ascon-XOF128

- **`Ascon_XOF_re_search_4.py`**  
  Re-search stage code for preimage attack on 4-round Ascon-XOF128

- **`Ascon_XOF_re_search_4_small.py`**  
  Small re-search stage code for preimage attack on 4-round Ascon-XOF128

- **`Ascon_XOF_re_search_4_small1.py`**  
  Alternative small re-search stage code for preimage attack on 4-round Ascon-XOF128

## Notes

- The attack code is typically split into multiple Python files corresponding to different stages of the overall workflow.
