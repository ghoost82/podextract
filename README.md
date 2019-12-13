# POD Extracter

Tool to extract files from Terminal Reality POD and EPD archives.

## How to use

```sh
$ python podextract.py  -h
usage: podextract.py [-h] [-l | -ll | -x] [-p PATTERN] file [dir]

Extract Terminal Reality POD and EPD archive files

positional arguments:
  file                  input POD/EPD file
  dir                   directory to where the files will be extracted

optional arguments:
  -h, --help            show this help message and exit
  -l, --list            list files of the POD file
  -ll, --listlong       list files of the POD file with size and time stamp
  -x, --extract         extract files from the POD file
  -p PATTERN, --pattern PATTERN
                        list or extract files that match the pattern only
```

## Incomplete list of Games using POD archives

- POD Version 1
  - Terminal Velocity
  - Fury3
  - Hellbender
  - Monster Truck Madness 1 & 2
  - CART Precision Racing
- EPD/Extended POD
  - Fly!
- POD Version 2
  - Nocturne
  - Blair Witch Volume 1: Rustin Parr
  - 4x4 Evo 1 & 2
- POD Version 3
  - Fly! 2
  - BloodRayne 1 & 2
  - BlowOut
  - Aeon Flux
  - Metal Slug Anthology
- POD Version 4
  - The King of Fighters Collection: The Orochi Saga
  - Samurai Shodown Anthology
- POD Version 5
  - Ghostbusters: The Video Game
- POD Version 6
  - Ghostbusters: The Video Game Remastered

## Credits

Information about the POD file format was taken from [jtrfp][], [DragonUnPACKer][], [Ghostbusters Unpack][] and [QuickBMS][]

[jtrfp]: https://github.com/jtrfp/jtrfp
[DragonUnPACKer]: https://github.com/elbereth/DragonUnPACKer
[Ghostbusters Unpack]: http://svn.gib.me/public/ghostbusters/trunk/
[QuickBMS]: https://aluigi.altervista.org/quickbms.htm
