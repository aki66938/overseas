import 'package:flutter/material.dart';

const primary = Color(0xff183c31);
const success = Color(0xff178353);
const successBackground = Color(0xffe4f5ec);
const secondary = Color(0xff25765a);
const muted = Color(0xff73827b);
const border = Color(0xffe1e9e5);
const warning = Color(0xffa36b16);
const canvas = Color(0xfff2f6f3);
const cardShadow = Color(0x0d183c31);
const railBackground = Color(0xff12382c);
const railText = Color(0xffedf5ef);
const railDot = Color(0xff71cf9a);
const railDivider = Color(0xff3c5c4e);
const railLabelStyle = TextStyle(fontSize: 10, color: Color(0xffa8c2b3));

ThemeData accessTheme(String? fontFamily) => ThemeData(
  useMaterial3: true,
  scaffoldBackgroundColor: canvas,
  fontFamily: fontFamily,
  fontFamilyFallback: const ['Microsoft YaHei', 'PingFang SC', 'sans-serif'],
  colorScheme: ColorScheme.fromSeed(
    seedColor: primary,
    primary: primary,
    secondary: secondary,
    surface: Colors.white,
  ),
  textTheme: const TextTheme(
    titleLarge: TextStyle(
      fontSize: 22,
      fontWeight: FontWeight.w600,
      color: primary,
    ),
    bodyMedium: TextStyle(fontSize: 14, color: primary, height: 1.35),
    bodySmall: TextStyle(fontSize: 13, color: muted),
  ),
  filledButtonTheme: FilledButtonThemeData(
    style: FilledButton.styleFrom(
      minimumSize: const Size(double.infinity, 36),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
    ),
  ),
  outlinedButtonTheme: OutlinedButtonThemeData(
    style: OutlinedButton.styleFrom(
      minimumSize: const Size(74, 28),
      side: const BorderSide(color: border),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      foregroundColor: primary,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(5)),
    ),
  ),
  textButtonTheme: TextButtonThemeData(
    style: TextButton.styleFrom(foregroundColor: secondary),
  ),
);
