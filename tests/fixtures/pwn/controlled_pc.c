#include <unistd.h>

int main(void) {
    char buf[80] = {0};
    read(0, buf, sizeof(buf));
    void (*fn)(void) = *(void (**)(void))(buf + 40);
    fn();
    return 0;
}
