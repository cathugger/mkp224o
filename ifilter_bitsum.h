#ifdef __GNUC__

static IFT ifilter_bitsum(IFT x)
{
	if (sizeof(IFT) == 16)
		return (((IFT) 1) <<
			(__builtin_popcountll((unsigned long long) (x >> (sizeof(IFT) * 8 / 2))) +
				__builtin_popcountll((unsigned long long) x))) - 1;
	if (sizeof(IFT) == 8)
		return (((IFT) 1) << __builtin_popcountll((unsigned long long) x)) - 1;

	return (((IFT) 1) << __builtin_popcount((unsigned int) x)) - 1;
}

#else

static IFT ifilter_bitsum(IFT x)
{
	int v = 0;
	while (x != 0) {
		x &= x - 1;
		v++;
	}
	return (((IFT) 1) << v) - 1;
}

#endif
