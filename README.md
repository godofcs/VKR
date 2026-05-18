# Гетерогенная реализация дерева Меркла на C++

Четыре структурно-разнородные реализации дерева Меркла на языке C++17 под
общим прикладным интерфейсом SPV-протокола. Каждая реализация поставляется
отдельной динамической библиотекой (`.so`), стенд испытаний подгружает их
через `dlopen` и проводит функциональные проверки, замеры производительности
и расчёт интегрального критерия сравнительной оценки.

В качестве криптографической хеш-функции используется header-only
[picosha2](https://github.com/okdshin/PicoSHA2) (SHA-256). Внешних
динамических зависимостей у проекта нет.

---

## Содержание

1. [Реализации](#реализации)
2. [Структура проекта](#структура-проекта)
3. [Требования к сборке](#требования-к-сборке)
4. [Сборка и запуск](#сборка-и-запуск)
5. [Подключение к стороннему проекту](#подключение-к-стороннему-проекту)
6. [Создание собственной реализации](#создание-собственной-реализации)
7. [Аналитический модуль и критерий K(r)](#аналитический-модуль-и-критерий-kr)
8. [Известные ограничения](#известные-ограничения)

---

## Реализации

| Реализация | Файл | Класс | Адресация листьев |
|---|---|---|---|
| Классическое бинарное дерево на `shared_ptr` | `MerkleTrees/MerkleTree/merkle_tree.cpp` | `MerkleTree` | по позиции |
| Оптимизированное бинарное дерево на массиве | `MerkleTrees/OptimizedMerkleTree/optimized_merkle_tree.cpp` | `VectorMerkleTree` | по позиции |
| Radix-дерево Меркла (16-ричный trie без сжатия) | `MerkleTrees/RadixMerkleTree/radix_merkle_tree.cpp` | `RadixMerkleTree` | по строковому ключу |
| Дерево Меркла-Патриции (Modified MPT) | `MerkleTrees/PatriciaMerkleTree/patricia_merkle_tree.cpp` | `PatriciaMerkleTree` | по строковому ключу |

Бинарные реализации используют интерфейс `IMerkleTree` из
`Interfaces/merkle_tree_interface.h` (адресация по позиции в исходной
последовательности). Trie-варианты используют одноимённый интерфейс
`IMerkleTree` из `Interfaces/merkle_trie_interface.h` (адресация по
строковому ключу). Это два разных интерфейса с одинаковым именем класса —
в один TU включать оба нельзя. На уровне `IFullClient`/`ILightClient`
(см. `Interfaces/merkle_client.h`) различие скрыто.

---

## Структура проекта

```
VKR/
├── Interfaces/
│   ├── merkle_client.h               # IFullClient, ILightClient (общий контракт SPV)
│   ├── merkle_tree_interface.h       # IMerkleTree для бинарных деревьев (по индексу)
│   └── merkle_trie_interface.h       # IMerkleTree для trie-вариантов (по ключу)
├── MerkleTrees/
│   ├── MerkleTree/
│   │   ├── merkle_tree.cpp           # реализация (≈ 290 строк)
│   │   ├── merkle_tree_dll.cpp       # обёртка с экспортом фабричных функций
│   │   └── libmerkle_tree.so         # результат сборки
│   ├── OptimizedMerkleTree/          # на массиве 2i / 2i+1 (≈ 230 строк)
│   ├── RadixMerkleTree/              # 16-ричный trie (≈ 320 строк)
│   └── PatriciaMerkleTree/           # Modified MPT с EXTENSION/LEAF/BRANCH (≈ 570 строк)
├── utils/
│   ├── struct.h                      # KeyValue { string key; string value; }
│   ├── string_sum.cpp                # вспомогательная функция (в проекте не используется)
│   └── SHA256/sha256.h               # picosha2 (header-only SHA-256)
├── tests/
│   ├── analyzer.h                  # модуль нормировки и интегрального критерия K(r)
│   ├── test_stand.cpp                # стенд по одной библиотеке
│   ├── compare_stand.cpp             # стенд с ранжированием по нескольким библиотекам
│   ├── build.sh                      # сборка 4 .so + двух стендов
│   └── run.sh                        # запуск test_stand по всем собранным .so
└── README.md
```

---

## Требования к сборке

- Компилятор с поддержкой стандарта C++17: GCC 9+ или Clang 10+.
- Linux семейства Debian/Ubuntu (целевая платформа разработки —
  Ubuntu 22.04 LTS, GCC 11). Стенд использует `/proc/self/statm` для
  оценки RSS, поэтому без модификации работает только под Linux.
- Bash (для скриптов `build.sh`/`run.sh`).
- Внешних библиотек устанавливать не требуется — `picosha2` лежит в
  составе проекта.

Используемые флаги: `-std=c++17 -O2 -Wall -fPIC -shared` для библиотек,
`-std=c++17 -O2 -Wall` для исполняемых модулей. Стенды линкуются с `-ldl`.

---

## Сборка и запуск

```bash
cd VKR/tests
./build.sh           # соберёт 4 .so, test_stand, compare_stand
./run.sh             # запустит test_stand по каждой собранной .so
```

`build.sh` собирает динамические библиотеки в каталогах
`MerkleTrees/<Имя>/` и оба стенда — в `tests/`.

`run.sh` принимает два опциональных аргумента — список размеров наборов
через запятую и число повторов на одну операцию:

```bash
./run.sh                          # размеры 1000,10000 (10 повторов)
./run.sh "100,1000,10000"         # свои размеры
./run.sh "100,1000" 100           # 100 повторов
```

### Прямой запуск `test_stand`

```bash
./test_stand <path-to-lib.so> [sizes_csv] [repeats]
# например:
./test_stand ../MerkleTrees/PatriciaMerkleTree/libpatricia_merkle_tree.so "100,1000" 10
```

По умолчанию: `sizes_csv = 1000,10000`, `repeats = 100` (внутри стенда; в
`run.sh` дефолт — 10).

### Запуск `compare_stand` с расчётом критерия K(r)

```bash
./compare_stand [--sizes 100,1000] [--repeats 10] \
                [--weights b,u,i,d,v,p,m,l] \
                <lib1.so> <lib2.so> [...]
```

`compare_stand` выполняет полный двухэтапный критерий из подраздела 1.3
работы: пороговую фильтрацию по функциональным и интеграционным
требованиям + аддитивную свёртку эксплуатационных показателей. Подробности —
ниже в разделе [Аналитический модуль](#аналитический-модуль-и-критерий-kr).

Пример:

```bash
./compare_stand --sizes 100,1000 --repeats 10 \
    ../MerkleTrees/MerkleTree/libmerkle_tree.so \
    ../MerkleTrees/OptimizedMerkleTree/liboptimized_merkle_tree.so \
    ../MerkleTrees/RadixMerkleTree/libradix_merkle_tree.so \
    ../MerkleTrees/PatriciaMerkleTree/libpatricia_merkle_tree.so
```

---

## Подключение к стороннему проекту

Каждая реализация экспортирует четыре фабричные функции с C-компоновкой —
имена единообразны во всех четырёх библиотеках:

```cpp
extern "C" {
    IFullClient*  CreateMerkleFullClient();
    ILightClient* CreateMerkleLightClient();
    void          DestroyMerkleFullClient(IFullClient*);
    void          DestroyMerkleLightClient(ILightClient*);
}
```

### Режим 1 — статическая линковка

```bash
g++ -std=c++17 -O2 my_app.cpp \
    -L<path>/MerkleTrees/MerkleTree -lmerkle_tree \
    -o my_app
```

`my_app.cpp` подключает только заголовок `Interfaces/merkle_client.h`.
При запуске бинарник должен находить нужную `.so` (через
`LD_LIBRARY_PATH` или размещение в `/usr/local/lib`).

### Режим 2 — динамическая загрузка

```cpp
#include "Interfaces/merkle_client.h"
#include <dlfcn.h>

void* h = dlopen("libmerkle_tree.so", RTLD_NOW);
auto create_full  = reinterpret_cast<IFullClient* (*)()>(dlsym(h, "CreateMerkleFullClient"));
auto destroy_full = reinterpret_cast<void (*)(IFullClient*)>(dlsym(h, "DestroyMerkleFullClient"));

IFullClient* full = create_full();
full->Build(data);
auto proof = full->RequestProof(key);
/*...*/
destroy_full(full);
dlclose(h);
```

Поскольку имена фабричных функций единообразны, переключение между
реализациями сводится к подмене имени `.so`.

### API в двух словах

```cpp
struct KeyValue { string key; string value; };

class IFullClient {
public:
    virtual void              Build(const vector<KeyValue>& data) = 0;
    virtual string            GetRootHash() const                 = 0;
    virtual void              Update(const KeyValue& kv)          = 0;
    virtual void              Delete(const string& key)           = 0;
    virtual vector<uint8_t>   RequestProof(const string& key)     = 0;
};

class ILightClient {
public:
    virtual void  SetRootHash(const string& root_hash)                          = 0;
    virtual bool  VerifyProof(const KeyValue& kv,
                              const vector<uint8_t>& proof_bytes) const         = 0;
};
```

`Update` совмещает Insert и собственно Update: если ключа в дереве нет —
вставляется, если есть — значение перезаписывается. После каждой мутирующей
операции на стороне `IFullClient` лёгкому клиенту необходимо передавать
актуальный корневой хеш через `SetRootHash`.

---

## Создание собственной реализации

Чтобы добавить пятую реализацию:

1. Создайте каталог `MerkleTrees/<Имя>/`.
2. Реализуйте классы, удовлетворяющие интерфейсам `IFullClient` и
   `ILightClient` из `Interfaces/merkle_client.h`.
3. Создайте обёртку `<имя>_dll.cpp` с экспортом четырёх фабричных функций (по образцу `merkle_tree_dll.cpp`).
4. Добавьте строку в `tests/build.sh`:
   ```bash
   build_lib "$ROOT/MerkleTrees/<Имя>" "<имя>_dll.cpp" "lib<имя>.so"
   ```
5. После сборки `run.sh` и `compare_stand` подхватят новую реализацию без модификации стенда.

---

## Аналитический модуль и критерий K(r)

Модуль `tests/analyzer.h` реализует двухэтапный критерий сравнительной оценки.

### Этап 1 — пороговый фильтр

Реализация исключается из дальнейшего сравнения, если не выполнено хотя бы
одно из требований:

- соответствие единому интерфейсу (`conforms_to_interface`);
- оформление в виде динамической библиотеки (`packaged_as_dll`);
- переносимость между ОС (`portable`);
- воспроизводимость сборки (`reproducible_build`);
- наличие документации (`has_documentation`);
- прохождение функциональных проверок стенда (`correctness_passed`).

В `compare_stand` первые пять флагов фиксируются как «выполнено» (они
обеспечиваются самим способом сборки и поставки), `correctness_passed`
определяется по результату прогона функциональных проверок.

### Этап 2 — аддитивная свёртка

Для каждого эксплуатационного показателя выполняется min-max-нормировка
к отрезку [0, 1] в направлении «больше — лучше»:

```
f_i(r) = (x_max - x_i) / (x_max - x_min)         для «меньше — лучше»
f_i(r) = 1                                       если x_max == x_min
```

`x_min` и `x_max` вычисляются по реализациям, прошедшим фильтр.
Лидирующая по показателю реализация получает 1, отстающая — 0,
остальные — линейно интерполированы.

Интегральный критерий:

```
K(r) = Σ w_i · f_i(r),   Σ w_i = 1,   w_i ≥ 0.
```

В `compare_stand` веса задаются опцией `--weights b,u,i,d,v,p,m,l`
(по умолчанию — единичные, нормируются модулем к Σ = 1). Порядок весов:

| позиция | показатель |
|---|---|
| `b` | время построения |
| `u` | среднее время обновления |
| `i` | среднее время вставки |
| `d` | среднее время удаления |
| `v` | среднее время верификации |
| `p` | размер сериализованного доказательства |
| `m` | прирост резидентной памяти при построении |
| `l` | размер бинарной библиотеки |

---
