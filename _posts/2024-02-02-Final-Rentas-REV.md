# WRITEUP rentas CTF 2024
![1](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image1.png?raw=true)

Welcome to the rentas CTF 2024 writeup challenge (Team scap3G04T) ! Let's learn together :'D

## Navigate
- [Reverse Engineering](#RE)

---
## RE
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
### Forbidden Memories

(Author: OS1RIS)

![2](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image2.png)

The challenge told us to engage in the game and identify potential issues with the credit. However, there are numerous stages to navigate before reaching the credit scene at the game's ending. Initially, upon downloading the file, there is uncertainty about the .bin file's nature. It could be a CD, DVD, or ROM, representing a broad spectrum of possibilities. 

![3](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image3.png)

Yet, after analyzing it in IDA and observing the mention of "Sony Computer Entertainment," there is a probability that it is linked to a gaming platform. Now we just need to verify the file of the .bin file using binwalk

```
Command:
binwalk rentas.bin
```

![4](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image4.png)

Checking the word "Sony" using strings command

![5](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image5.png)

Now, we need to find a hidden clue or flag in the game's credits, as the challenge told. To Look at the names, symbols, or messages in the credits after completing the game to spot the required clue or flag, i started the ghidra and use x86 with a gcc as the compiler.

![6](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image6.png)

Here some results summary

![7](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image7.png)

During my search for the string in the rentas.bin file, I came across some intriguing words related to the challenge creator: "Gemas Lestari Atoy Comel Thankyou."

![8](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image8.png)

As we scroll a bit, we've stumbled upon a clue that resembles a credit scene after completing the game. Numerous names are listed above, resembling typical credits in a game. Keep exploring to confirm if this is indeed the credit scene the challenge is referring to.

![9](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image9.png)

![10](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image10.png)

To confirm the existence of the word, let's use the "strings" command once again to check if the specific word, "Gemas Lestari Atoy Comel Thankyou," is present in the file. This will help us validate the discovery.

![11](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image11.png)

Since I couldn't locate a .bin extractor to inspect the card information for "Exodia," and we don't want to waste time, let's explore an alternative. We can try finding the Exodia card by directly booting the game. This approach may provide a quicker way to access and identify the desired card within the game itself.In the search for a .bin file linked to the game, the initial suggestion is to explore PCSX. It appears that I'm facing difficulties booting the game using PCSX. I've been exploring alternatives to launch the PS1 game through a different method, and duckstation was the most stable for my PC.

![12](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image12.png)

![13](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image13.png)

While attempting to run the game, an issue arises indicating that the current BIOS is not compatible. It seems the .bin file must be NTSC-U/C from the US or Canada.

![14](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image14.png)

To address the compatibility issue, download the BIOS specifically for Canada or the US.

![15](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image15.png)

![16](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image16.png)

After inserting the new BIOS and running the game, everything works perfectly fine. Now, let's proceed and enjoy playing the game a bit further.

![17](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image17.png)

![18](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image18.png)

After an extended gaming session, the difficulty of the game keeps increasing. To overcome this, it's time to utilize the cheat manager.

![19](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image19.png)

Fortunately, DuckStation has already detected the cheat list for this game. Simply tick all the cheats to become overpowered and enjoy the gameplay.

![20](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image20.png)

After utilizing the cheat manager to ensure the cards, it's crucial to double-check the hint.

![21](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image21.png)

```
RAWSEC(SEETHEEXODIACARD )
```

Now, our next step is to halt at the character named Heishin, opt for the 'Duel' selection, and proceed to the chest to construct the deck or card set. By doing this, we can progress further in the game. 

![22](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image22.png)

P/S: I'm a big fan of YuGiOh, which explains why I'm familiar with some of its details.

![23](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image23.png)

When you choose "Exodia the Forbidden," notice the end of the flag format. This might be a good sign to search for more parts. Keep an eye out for additional clues or elements to make progress in the challenge.

![24](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image24.png)

Searching on Google for images of all the parts of Exodia reveals a total of five parts. Now, the task is to find the remaining pieces.

![25](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image25.jpeg)

Examining the names of the cards in the image above and cross-referencing them with the in-game card numbers, it appears that the remaining pieces start from card number 17 and go up to card number 21.

![26](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image26.png)

Now we just need to open all the cards information.

![27](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image27.png)

```
Source : https://yugioh.fandom.com/wiki/List_of_Yu-Gi-Oh!_Forbidden_Memories_cards
```

Now for every part:

![28](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image28.png)

PART 1: RWSC{

![29](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image29.png)

PART 2: TH3_

![30](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image30.png)

PART 3: P0W3R_

![31](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image31.png)

PART 4: 0f_

![32](https://raw.githubusercontent.com/plnsgr/os1ris/main/rentas%20CTF/images/image24.png)

PART 5: 3X0D14}

Combining the flag results in:

```
Flag: RWSC{TH3_P0W3R_0f_3X0D14}
```
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
