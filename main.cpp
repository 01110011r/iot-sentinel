#include <iostream>
#include <vector>

int main() {
    int n;
    std::cout << "Massiv elementlari sonini kiriting: ";
    if (!(std::cin >> n) || n <= 0) {
        return 1;
    }

    std::vector<int> arr(n);
    std::cout << n << " ta elementni kiriting: ";
    for (int i = 0; i < n; ++i) {
        std::cin >> arr[i];
    }

    long long even_idx_sum = 0;
    long long odd_idx_sum = 0;

    for (int i = 0; i < n; ++i) {
        if (i % 2 == 0) {
            even_idx_sum += arr[i];
        } else {
            odd_idx_sum += arr[i];
        }
    }

    std::cout << "Juft indeksdagi elementlar yig'indisi: " << even_idx_sum << std::endl;
    std::cout << "Toq indeksdagi elementlar yig'indisi: " << odd_idx_sum << std::endl;

    return 0;
}
