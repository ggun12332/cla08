#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;
#define INT_MAX 0x7fffffff

int n;
vector<int> a, maxTree, minTree;

// 세그먼트 트리 초기화
void init(int node, int nodeLeft, int nodeRight) {
    if (nodeLeft == nodeRight) {
        maxTree[node] = a[nodeLeft];
        minTree[node] = a[nodeLeft];
        return;
    }

    int mid = (nodeLeft + nodeRight) / 2;

    init(
        node * 2,
        nodeLeft,
        mid
    );

    init(
        node * 2 + 1,
        mid + 1,
        nodeRight
    );

    maxTree[node] = max(maxTree[node * 2], maxTree[node * 2 + 1]);
    minTree[node] = min(minTree[node * 2], minTree[node * 2 + 1]);
}

// 세그먼트 트리 갱신
void update(int node, int nodeLeft, int nodeRight, int queryIndex, int value) {
    if (queryIndex < nodeLeft || nodeRight < queryIndex) {
        return;
    }

    if (nodeLeft == nodeRight) {
        maxTree[node] = value;
        minTree[node] = value;
        return;
    }

    int mid = (nodeLeft + nodeRight) / 2;

    update(
        node * 2,
        nodeLeft,
        mid,
        queryIndex,
        value
    );

    update(
        node * 2 + 1,
        mid + 1,
        nodeRight,
        queryIndex,
        value
    );

    maxTree[node] = max(maxTree[node * 2], maxTree[node * 2 + 1]);
    minTree[node] = min(minTree[node * 2], minTree[node * 2 + 1]);
}

// 최대값 쿼리
int queryMax(int node, int nodeLeft, int nodeRight, int queryLeft, int queryRight) {
    if (queryRight < nodeLeft || nodeRight < queryLeft) {
        return 0;
    }

    if (queryLeft <= nodeLeft && nodeRight <= queryRight) {
        return maxTree[node];
    }

    int mid = (nodeLeft + nodeRight) / 2;
    int leftMax = queryMax(
        node * 2,
        nodeLeft,
        mid,
        queryLeft,
        queryRight
    );
    int rightMax = queryMax(
        node * 2 + 1,
        mid + 1,
        nodeRight,
        queryLeft,
        queryRight
    );

    return max(leftMax, rightMax);
}

// 최소값 쿼리
int queryMin(int node, int nodeLeft, int nodeRight, int queryLeft, int queryRight) {
    if (queryLeft > nodeRight || queryRight < nodeLeft) {
        return INT_MAX;
    }

    if (queryLeft <= nodeLeft && nodeRight <= queryRight) {
        return minTree[node];
    }

    int mid = (nodeLeft + nodeRight) / 2;
    int leftMin = queryMin(
        node * 2,
        nodeLeft,
        mid,
        queryLeft,
        queryRight
    );
    int rightMin = queryMin(
        node * 2 + 1,
        mid + 1,
        nodeRight,
        queryLeft,
        queryRight
    );

    return min(leftMin, rightMin);
}

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);
    
    int t;
    cin >> t;

    for (int test = 1; test <= t; test++) {
        cin >> n;
        int m;
        cin >> m;

        cout << "#" << test << " ";
        
        a.resize(n);
        maxTree.resize(4 * n);
        minTree.resize(4 * n);

        for (int i = 0; i < n; i++) {
            cin >> a[i];
        }

        init(1, 0, n - 1);

        for (int i = 0; i < m; i++) {
            int query, left, right;
            cin >> query >> left >> right;

            if (query == 0) {
                update(1, 0, n - 1, left, right);
            } else if (query == 1) {
                int maxVal = queryMax(1, 0, n - 1, left, right - 1);
                int minVal = queryMin(1, 0, n - 1, left, right - 1);
                cout << maxVal - minVal << " ";
            }
        }
        cout << "\n";
    }

    return 0;
}
