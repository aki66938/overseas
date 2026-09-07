# Golden test font

Noto Sans SC variable font, upstream Google Fonts, SIL OFL 1.1; notice in `OFL.txt`.
Retrieved 2026-09-07 from the official `google/fonts` repository. Upstream HEAD at retrieval:
`5e35378e6bda803962ee6fd257e444a7d459660d`.

Source: https://raw.githubusercontent.com/google/fonts/5e35378e6bda803962ee6fd257e444a7d459660d/ofl/notosanssc/NotoSansSC%5Bwght%5D.ttf

SHA256: `a3041811a78c361b1de50f953c805e0244951c21c5bd412f7232ef0d899af0da`.

The unmodified single font file avoids a new subset-generation toolchain and missing Chinese glyphs.
It is loaded directly by tests only, not declared in pubspec or shipped with the application.
Production uses desktop system fonts and never downloads fonts. Material icons come from the pinned Flutter SDK.
Goldens pin Flutter 3.47.2 on Windows, a 460×540 logical viewport, DPR 1, fixed clock and synthetic fixtures.
Use `flutter test --update-goldens test/goldens_test.dart` after reviewing intended visual changes.
Pixel baselines do not verify native window chrome or actual macOS font rendering; native host integration remains a separate gate.
