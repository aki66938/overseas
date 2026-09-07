import 'package:flutter/material.dart';

const primary = Color(0xff183c31);
const success = Color(0xff178353);
const successBackground = Color(0xffe4f5ec);
const secondary = Color(0xff25765a);
const muted = Color(0xff73827b);
const border = Color(0xffe1e9e5);
const warning = Color(0xffa36b16);

ThemeData accessTheme(String? fontFamily) => ThemeData(
  useMaterial3: true,
  scaffoldBackgroundColor: Colors.white,
  fontFamily: fontFamily,
  fontFamilyFallback: const ['Microsoft YaHei', 'PingFang SC', 'sans-serif'],
  colorScheme: ColorScheme.fromSeed(
    seedColor: primary,
    primary: primary,
    secondary: secondary,
    surface: Colors.white,
  ),
  textTheme: const TextTheme(
    bodyMedium: TextStyle(fontSize: 14, color: primary),
    bodySmall: TextStyle(fontSize: 13, color: muted),
  ),
  filledButtonTheme: FilledButtonThemeData(
    style: FilledButton.styleFrom(
      minimumSize: const Size(double.infinity, 48),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
    ),
  ),
  outlinedButtonTheme: OutlinedButtonThemeData(
    style: OutlinedButton.styleFrom(
      minimumSize: const Size(double.infinity, 44),
      side: const BorderSide(color: border),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
    ),
  ),
  textButtonTheme: TextButtonThemeData(
    style: TextButton.styleFrom(foregroundColor: secondary),
  ),
);
