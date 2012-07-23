#!/usr/bin/perl -w
use strict;
no warnings 'portable';  # Support for 64-bit ints required

my $HX="(?:0x)?[0-9,a-f,A-F]+";
my @vmas;
my $last_vma;

sub find_vma
{
    my $ip = shift;

    # It seems to be reasonable to cache last VMA since near calls 
    # are usually localized within one module
    if (defined($last_vma) &&
        $ip >= $last_vma->{vmstart} && $ip < $last_vma->{vmend}) {
        return $last_vma;
    }

    my ($l, $h) = (0, scalar(@vmas));

    # assume non-overlapped mapping
    while($l < $h) 
    {
        my $i = int(($l + $h) / 2);
        if ($ip < $vmas[$i]->{vmstart}) {
            $h = $i;
        }
        elsif ($ip >= $vmas[$i]->{vmend}) {
            $l = $i + 1;
        }
        else {
            $last_vma = $vmas[$i];
            return $last_vma;
        }
    }

    return undef;
}

sub extract_xsections
{
    my $vma = shift;
    my $n = 0;
    
    if ($vma->{file} ne "") {
        open(my $ELFDUMP, "-|", "readelf -W -S $vma->{file}") or die("Failed to readelf $vma->{file}: $!");
        while(<$ELFDUMP>)
        {
            if (/^\s*\[.*?\]\s+(\S+)\s+\w+\s+$HX\s+($HX)\s+($HX)\s+\d+\s+(\w+)/) {
                my $flags = $4;
                if (index($flags, 'X') != -1) {
                    my %section = ( name   => $1, 
                                    offset => hex($2), 
                                    size   => hex($3)
                                  );

                    push @{ $vma->{xsections} }, \%section;
                    $n++;
                }
            }
        }
        close $ELFDUMP;
    }

    return $n & 1;
}

sub find_xsection
{
    my ($vma, $offset) = @_;

    unless (defined $vma->{xsections}) {
        undef unless extract_xsections($vma);
    }

    foreach (@{ $vma->{xsections} }) {
        if ($offset >= $_->{offset} && 
            $offset < ($_->{offset} + $_->{size}))
        {
            return $_;
        }
    }

    return undef;
}

##
# The most unefficient thing:
# dynamic loader (ex. ld.so(8)) uses .hash section to quickly 
# find addr by symbol-name, but here we need inverted search: symbol by addr.
sub find_dynsym
{
    my ($vma, $offset) = @_;

    # It's better to use readelf --dyn-sym, but not available in all versions
    # TODO: pick a right option depend on `readelf -v`

    open(my $DYNSYMS, "-|", "readelf -dWs $vma->{file}") or return undef;
    printf("*** readelf -dWs $vma->{file}\n");
    while(<$DYNSYMS>) {
        # Num:    Value          Size Type    Bind   Vis      Ndx Name
        if (/\d+:\s+($HX)\s+(\d+)\s+\w+\s+\w+\s+\w+\s+\w+\s+(.*)$/) {
            my ($addr, $size, $name) = (hex($1), $2, $3);
            if ($offset >= $addr && $offset < $addr + $size) {
                return $name;
            }
        }
    }
    close $DYNSYMS;
    return undef;
}

sub get_symbol_info
{
    my ( $vma, $xs, $offset ) = @_;
    my $out = "";

    my $xs_offset = $offset - $xs->{offset};
    printf("*** found X-section: %s - offset:0x%x (%d bytes within | %d abs)\n", $xs->{name}, $xs->{offset}, $xs_offset, $offset);

    my $cmd = sprintf("addr2line -e %s -fj %s 0x%x", $vma->{file}, $xs->{name}, $xs_offset);
    printf("*** exec $cmd\n");

    open(my $ADDR2LINE, "-|", "$cmd") or die("Failed to $cmd");
    my ($fn, $srcaddr) = <$ADDR2LINE>;
    chomp $fn;
    chomp $srcaddr;
    close $ADDR2LINE;

    if ($fn eq "??") {
        # addr2line(1) can extract only global symbol table.
        # But we can always find GLOBAL symbol name in shared object same way
        # like dynamic loader does.
        $out = find_dynsym($vma, $offset) || "-";
    }
    else {
        $out = ($srcaddr eq "??:0") ? $fn  : "$fn ($srcaddr)";
    }

    return $out;
}

sub print_frameinfo
{
    my $ip = shift;
    my $vma = find_vma($ip);

    unless (defined $vma) {
        return sprintf("0x%x - unknown (unmapped) VMA\n", $ip);
    }

    printf("*** found VMA: %s 0x%x\n", $vma->{file}, $vma->{offset});

    my $offset = $ip - $vma->{vmstart} + $vma->{offset};
    my $xs = find_xsection($vma, $offset);
    if (defined $xs) {
        my $d_info = get_symbol_info($vma, $xs, $offset);
        return "$vma->{file}: " . $d_info;
    }

    return sprintf("unknown section for $offset at $vma->{file}");
}

my $pid = $ARGV[0];
open (my $MAPS, "<", "/proc/$pid/maps") or die "Failed to open maps file (/proc/$pid/maps): $!";
while(<$MAPS>)
{
    if (/^($HX)-($HX)\s+([rwxp-]+)\s($HX)\s+$HX:$HX\s+\d+\s*(.*)?/)
    {
        my $perms = $3;
        if (index($perms, 'x') != -1)
        {
            my %region = ( vmstart => hex($1), 
                           vmend   => hex($2),
                           offset  => hex($4),
                           file    => (defined $5) ? $5 : ""
                         );

            push @vmas, \%region;
        }
    }
}
close $MAPS;

@vmas = sort { $a->{vmstart} <=> $b->{vmstart} } @vmas;
shift @ARGV;

my $i = 0;
while(<>)
{
    chomp;
    my $ip = hex;
    my $inf = print_frameinfo($ip);
    printf("#%-2d 0x%016x in %s\n", $i++, $ip, $inf);
}
