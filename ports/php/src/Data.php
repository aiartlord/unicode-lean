<?php

declare(strict_types=1);

namespace UnicodePhp;

/// Self-contained data-directory resolution. Every UCD / security data file the
/// port reads at runtime lives under `ports/php/data/`; the port never reaches
/// into the repository-root `data/`, `Unicode/`, or `fixtures/` trees. The
/// digest gate (`SHA256SUMS`) pins the bundled files to UCD 17.0.0.
final class Data
{
    /// Absolute path to the bundled data directory.
    public static function dir(): string
    {
        return dirname(__DIR__) . '/data';
    }

    /// Read a bundled data file's full contents as a string.
    public static function read(string $relative): string
    {
        $path = self::dir() . '/' . $relative;
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new \RuntimeException("Data: cannot read bundled file '{$relative}'");
        }
        return $contents;
    }

    /// The bundled files split into individual lines (no trailing-empty
    /// artifact beyond what the source carries), matching the `.lines()`
    /// iteration the reference ports use over their embedded strings.
    public static function lines(string $relative): array
    {
        $contents = self::read($relative);
        // Mirror Rust `str::lines`: split on "\n", dropping a single trailing
        // "\r" per line and a single final empty element from a trailing "\n".
        $raw = explode("\n", $contents);
        if ($raw !== [] && $raw[count($raw) - 1] === '') {
            array_pop($raw);
        }
        return array_map(static fn (string $line): string => rtrim($line, "\r"), $raw);
    }
}
