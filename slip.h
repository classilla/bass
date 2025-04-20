int slip_setup();
#if __GNUC__
B16 slip_sum(SCH *payload, int size);
int slip_ship(SCH *payload, int size);
int slip_splat(SCH *payload, int size);
int slip_slurp(SCH *payload, int size);
#else
B16 slip_sum();
int slip_ship();
int slip_splat();
int slip_slurp();
#endif
int slip_stop();
