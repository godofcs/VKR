#include <string>
using namespace std;

const char trans[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

string sum(string& left, string& right) {
	string ans;
	int pred = 0;
	for (int i = 0; i < left.size(); ++i) {
		int c1, c2;
		if ('0' <= left[i] && left[i] <= '9') c1 = left[i] - '0';
		if ('a' <= left[i] && left[i] <= 'f') c1 = left[i] - 'a' + 10;
		if ('0' <= right[i] && right[i] <= '9') c2 = right[i] - '0';
		if ('a' <= right[i] && right[i] <= 'f') c2 = right[i] - 'a' + 10;
		int rez = c1 + c2 + pred;
		pred = rez / 16;
		rez %= 16;
		ans.push_back(trans[rez]);
	}
	if (pred != 0) {
		ans.push_back(trans[pred]);
	}

	return move(ans);
}