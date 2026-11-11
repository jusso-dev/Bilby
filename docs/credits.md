# Credits

## Bilby photographs

Bilby uses two photographs, cropped and resized. Both are © State of Queensland and licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). The app shows this credit under the home screen photo and in Settings, under "About Bilby".

| File in the app | Original | What was changed |
|---|---|---|
| `app/ui/img/bilby-burrow.jpg` | "Greater bilby at its burrow, Astrebla Downs National Park, 2024", [Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Greater_bilby_at_its_burrow,_Astrebla_Downs_National_Park,_2024.jpg), 5472×3648 | Cropped to a wide banner and resized to 1408×640. |
| `app/ui/img/bilby-face.jpg` | "Macrotis lagotis1.jpg", [Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Macrotis_lagotis1.jpg), 650×553 | Cropped square around the face, 400×400. |
| `app/src-tauri/icons/*` | The same "Macrotis lagotis1.jpg" | Cropped square, scaled to 1024×1024, then made into the app icons with `cargo tauri icon`. |

Both Commons pages give the State of Queensland as the source, under the Queensland Government's CC BY 4.0 website licence. Neither names a photographer. That licence excludes third-party material whether or not it's labelled, and Queensland only promises to label it where practicable, so a missing label doesn't prove the State owns these photos. Ask the Queensland Department of the Environment to confirm before a public release, or swap in the public domain fallback in the next paragraph.

Public domain fallback, if Queensland can't confirm: "Bilby at Sydney Wildlife World" by Dcoetzee, [Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Bilby_at_Sydney_Wildlife_World.jpg).

Licences checked 2026-11-11. Photos with CC BY-SA, NC or ND licences weren't used: ShareAlike would bind the app's artwork, and NC or ND can't be used at all.
