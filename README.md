# Гетерогенная реализация дерева Меркла на C++

Четыре единообразно реализованные версии дерева Меркла на языке C++17 — для применения в задачах упрощённой верификации платежей в блокчейне (SPV), аутентифицированного хранения key-value состояния и других сценариев, где требуется компактное доказательство принадлежности данных множеству.

Все реализации используют криптографическую хеш-функцию **SHA-256** (заголовочная библиотека [picosha2](https://github.com/okdshin/PicoSHA2)) и работают с парами ключ–значение типа `KeyValue`.

---

## Содержание

1. [Что реализовано](#что-реализовано)
2. [Структура проекта](#структура-проекта)
3. [Требования к сборке](#требования-к-сборке)
4. [Подключение в свой проект](#подключение-в-свой-проект)
5. [Использование](#использование)
6. [Создание собственной реализации](#создание-собственной-реализации)
7. [Запуск тестирования](#запуск-тестирования)
8. [Сравнительные характеристики](#сравнительные-характеристики)
9. [Когда какую реализацию выбирать](#когда-какую-реализацию-выбирать)

---

## Что реализовано

| Реализация | Класс | Файл | Адресация листьев |
|---|---|---|---|
| Классическое дерево на `shared_ptr` | `MerkleTree` | `merkle_tree.cpp` | по индексу |
| Оптимизированное дерево на `vector<string>` | `MerkleTree` | `optimized_merkle_tree.cpp` | по индексу |
| Radix-дерево Меркла | `RadixMerkleTree` | `radix_merkle_tree.cpp` | по ключу |
| Дерево Меркла-Патриции | `PatriciaMerkleTree` | `patricia_merkle_tree.cpp` | по ключу |

Бинарные реализации (классическая и оптимизированная) работают с интерфейсом `IMerkleTree` из `Interfaces/merkle_tree_interface.h` — адресация по позиции в исходной последовательности.

Trie-варианты (Radix и Patricia) работают с интерфейсом `IMerkleTree` из `Interfaces/merkle_trie_interface.h` — адресация по строковому ключу. Это два разных интерфейса с одинаковым именем, разделение обусловлено принципиально различной моделью адресации листьев.

---

## Структура проекта

```
VKR-master/
└── Merkle trees/
    ├── Interfaces/
    │   ├── merkle_tree_interface.h        # IMerkleTree для бинарных деревьев (по индексу)
    │   └── merkle_trie_interface.h        # IMerkleTree для trie-вариантов (по ключу)
    ├── Merkle tree/
    │   ├── merkle_tree.cpp                # классическое на shared_ptr
    │   ├── optimized_merkle_tree.cpp      # на массиве (компактная индексация 2i, 2i+1)
    │   ├── radix_merkle_tree.cpp          # 16-арное Radix-дерево
    │   └── patricia_merkle_tree.cpp       # дерево Меркла-Патриции
    ├── utils/
    │   ├── struct.h                       # тип KeyValue
    │   ├── string_sum.cpp                 # конкатенация строк
    │   └── SHA256/sha256.h                # picosha2
    └── tests/
        ├── test_generator.cpp             # тесты для бинарных деревьев
        ├── test_trie_generator.cpp        # тесты для trie-вариантов
        └── Makefile
```

---

## Требования к сборке

- Компилятор с поддержкой C++17 (GCC 9+, Clang 10+)
- POSIX-окружение (Linux, macOS) — для замера памяти в тестах через `getrusage` и `/proc/self/statm`
- GNU Make — для сборки тестов

Внешних зависимостей нет — `picosha2` поставляется в составе проекта.

---

## Подключение в свой проект

### Бинарное дерево Меркла

Подключите один из двух файлов:

```cpp
#include "Merkle tree/merkle_tree.cpp"            // на shared_ptr
// или
#include "Merkle tree/optimized_merkle_tree.cpp"  // на массиве (быстрее)
```

В обоих файлах класс называется `MerkleTree`. Если нужно использовать обе версии в одном проекте, оберните их в namespace или переименуйте макросом — пример такой схемы можно посмотреть в `tests/test_generator.cpp`.

### Trie-варианты

```cpp
#include "Merkle tree/radix_merkle_tree.cpp"      // Radix
// или
#include "Merkle tree/patricia_merkle_tree.cpp"   // Patricia (рекомендуется)
```

Классы называются `RadixMerkleTree` и `PatriciaMerkleTree` — конфликта имён нет. Но интерфейс `IMerkleTree` определяется в обоих файлах (через общий заголовок), поэтому без include guards подключать оба `.cpp` сразу в одну единицу трансляции нельзя — компилируйте их раздельно.

---

## Использование

### Тип `KeyValue`

```cpp
struct KeyValue {
    std::string key;
    std::string value;
};
```

Ключ — как правило, шестнадцатеричное представление SHA-256-хеша исходного ключа (64 символа). Значение — произвольная строка.

### Бинарное дерево Меркла

```cpp
#include "Merkle tree/optimized_merkle_tree.cpp"
#include <vector>
#include <iostream>

int main() {
    // Подготовка набора данных
    std::vector<KeyValue> data;
    for (int i = 0; i < 1000; ++i) {
        KeyValue kv;
        kv.key   = picosha2::hash256_hex_string("tx_" + std::to_string(i));
        kv.value = "amount: " + std::to_string(i);
        data.push_back(kv);
    }

    // Построение дерева
    MerkleTree tree(data);

    // Корневой хеш (для записи в заголовок блока)
    std::cout << "Root: " << tree.GetRootHash() << "\n";

    // Верификация принадлежности (центральная операция SPV)
    std::string key = data[42].key;
    bool ok = tree.VerifyValue(42, key);

    // Получение значения по индексу
    std::string value = tree.GetValue(42);

    // Обновление значения
    KeyValue new_kv = { data[42].key, "new_amount" };
    tree.UpdateValue(new_kv, 42);

    // Удаление элемента (со сдвигом последующих)
    tree.DeleteValue(42);
}
```

### Дерево Меркла-Патриции

```cpp
#include "Merkle tree/patricia_merkle_tree.cpp"
#include <iostream>

int main() {
    // Способ 1: пустое дерево + последовательные вставки
    PatriciaMerkleTree tree;

    KeyValue kv;
    kv.key   = picosha2::hash256_hex_string("0xAlice");
    kv.value = "1000";
    tree.UpdateValue(kv);

    // Корневой хеш
    std::cout << "Root: " << tree.GetRootHash() << "\n";

    // Верификация и получение
    if (tree.VerifyValue(kv.key)) {
        std::cout << "value = " << tree.GetValue(kv.key) << "\n";
    }

    // Удаление по ключу
    tree.DeleteValue(kv.key);

    // Способ 2: построение из готового набора
    std::vector<KeyValue> data = /* ... */ {};
    PatriciaMerkleTree from_data(data);
}
```

### Radix-дерево Меркла

Использование идентично Patricia — общий интерфейс:

```cpp
#include "Merkle tree/radix_merkle_tree.cpp"

RadixMerkleTree tree;
tree.UpdateValue({ hex_key, "value" });
bool ok = tree.VerifyValue(hex_key);
std::string v = tree.GetValue(hex_key);
tree.DeleteValue(hex_key);
```

---

## Создание собственной реализации

### Бинарное дерево (адресация по индексу)

```cpp
#include "../Interfaces/merkle_tree_interface.h"
#include "../utils/SHA256/sha256.h"

class MyMerkleTree : public IMerkleTree {
public:
    MyMerkleTree() = default;
    MyMerkleTree(std::vector<KeyValue>& data) {
        // Построение дерева по data
    }
    ~MyMerkleTree() override = default;

    std::string GetRootHash() override                       { /* ... */ }
    void        DeleteValue(int index) override             { /* ... */ }
    void        UpdateValue(KeyValue& kv, int index) override { /* ... */ }
    bool        VerifyValue(int index, std::string& key) override { /* ... */ }
    std::string GetValue(int index) override                { /* ... */ }
};
```

### Trie-вариант (адресация по ключу)

```cpp
#include "../Interfaces/merkle_trie_interface.h"
#include "../utils/SHA256/sha256.h"

class MyTrieTree : public IMerkleTree {
public:
    MyTrieTree() = default;
    MyTrieTree(const std::vector<KeyValue>& data) {
        for (const auto& kv : data) UpdateValue(kv);
    }
    ~MyTrieTree() override = default;

    std::string GetRootHash() override                          { /* ... */ }
    void        DeleteValue(const std::string& key) override   { /* ... */ }
    void        UpdateValue(const KeyValue& kv) override       { /* ... */ }
    bool        VerifyValue(const std::string& key) override   { /* ... */ }
    std::string GetValue(const std::string& key) override      { /* ... */ }
};
```

После реализации новый класс автоматически совместим с тестовым каркасом — достаточно подменить `using TestedMerkleTree = ...` или `using TestedTrie = ...` в соответствующем тестовом файле.

---

## Запуск тестирования

В каталоге `tests/` находятся два тестовых файла, реализующих нагрузочное тестирование с замером времени всех основных операций и потребления памяти.

### Сборка

```bash
cd "Merkle trees/tests"
make all
```

Будет собрано четыре бинарника:

| Бинарник | Тестируемая реализация |
|---|---|
| `test_pointer` | бинарное дерево на `shared_ptr` |
| `test_vector` | бинарное дерево на `vector<string>` |
| `test_radix` | Radix-дерево Меркла |
| `test_patricia` | дерево Меркла-Патриции |

### Прогон тестов с размерами по умолчанию

```bash
make run        # все четыре теста подряд
make run-bin    # только бинарные деревья
make run-trie   # только trie-варианты
```

Размеры по умолчанию:

| Тест | Размеры наборов данных |
|---|---|
| `test_pointer`, `test_vector` | 1 000, 10 000, 100 000, от 1·10⁶ до 1·10⁷ с шагом 1·10⁶ |
| `test_radix` | 1 000, 10 000, 100 000 (на бо́льших — нехватка памяти) |
| `test_patricia` | 1 000, 10 000, 100 000, 1·10⁶ |

### Прогон с произвольными размерами

Передайте размеры как первый аргумент через запятую:

```bash
./test_pointer "1000,10000,100000"
./test_patricia "1000,10000,100000,500000,1000000"
./test_radix "5000,20000"
```

### Что замеряется

Для каждой реализации и каждого размера набора измеряется:

- **build** — время построения дерева по полному набору
- **verify** — среднее время одной верификации принадлежности
- **get** — среднее время одной выборки значения по ключу (только trie)
- **update** — среднее время одного точечного обновления
- **delete** — среднее время одного удаления (только trie)
- **mem build** — пиковый прирост RSS при построении (объём памяти, занимаемой деревом)
- **RSS after** — текущий RSS сразу после построения (на Linux — точное значение из `/proc/self/statm`)
- **peak** — пиковый RSS за весь прогон (только бинарные тесты)

### Пример вывода

```
==============================================================
Implementation: Merkle Tree on vector<string>
Hash function:  SHA-256 (picosha2)
==============================================================
Run for n = 10000 ... done in 2.7 s.
Run for n = 100000 ... done in 3.2 s.

--- Summary ----------------------------------------------------
n =    10000 | build =     25.760 ms | verify avg =    0.029 ms | update avg =     23.584 ms | mem build =     4.1 MB | RSS after =     8.4 MB | peak =     8.2 MB
n =   100000 | build =    247.530 ms | verify avg =    0.039 ms | update avg =    259.427 ms | mem build =    41.2 MB | RSS after =    57.9 MB | peak =    57.8 MB
----------------------------------------------------------------
Last root hash: e7a172a404482123cd512fb7640d13e19322785c2ff1376157ec35132dc341c8
```

### Очистка

```bash
make clean
```

---

## Сравнительные характеристики

| Структура | Адресация | Поиск/верификация | Размер доказательства | Точечное обновление |
|---|---|---|---|---|
| Классическое дерево Меркла | по позиции | O(log n) | O(log n) | O(log n) |
| Дерево Меркла на массиве | по позиции | O(log n) | O(log n) | O(log n) |
| Radix-дерево Меркла | по ключу | O(L) | O(L · (r − 1)) | O(L) |
| Дерево Меркла-Патриции | по ключу | O(log_r n) среднее | O(log_r n) среднее | O(log_r n) среднее |

где n — число хранимых пар ключ–значение, L — длина ключа в символах основания r (для SHA-256 в hex: r = 16, L = 64).

---

## Когда какую реализацию выбирать

| Сценарий применения | Рекомендуемая реализация | Причина |
|---|---|---|
| Bitcoin SPV (статичный набор транзакций блока) | бинарное дерево на массиве | Минимальный размер доказательства, наилучшая локальность по кэшу |
| Аутентифицированное хранение динамического key-value состояния (Ethereum-style) | дерево Меркла-Патриции | Эффективное обновление по ключу, разумные затраты памяти |
| Ситуация, когда нужны явные ссылки на узлы дерева | бинарное дерево на `shared_ptr` | Удобно для интеграции с другими структурами C++-проекта |
| Учебно-исследовательский разбор trie-конструкции | Radix-дерево Меркла | Простая структура без сжатия путей, легче для понимания |

Использовать Radix-дерево в продакшн-системах, как правило, нецелесообразно: оно создаёт ~64 узла на каждый ключ и не масштабируется по памяти за пределы примерно 100 тысяч элементов. Если нужны свойства упорядоченной по ключу адресации — выбирайте Patricia.

---

## Лицензия

Учебный проект. Разработан в рамках выпускной квалификационной работы бакалавра по теме «Исследование применимости и производительности гетерогенной реализации дерева Меркла в операциях по упрощённой верификации платежей в блокчейне».
