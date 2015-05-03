#include <extalk.h>
int main()
{
    int x = 1;
    char *p = (char *)&x;
    if(*p)
        printf("\n Little endian");//Lower byte has LSB of an int
    else
        printf("\n Big endian");//Higher byte has LSB of int
}
