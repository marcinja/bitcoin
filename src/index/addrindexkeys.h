#ifndef BITCOIN_INDEX_ADDRINDEXKEYS_H
#define BITCOIN_INDEX_ADDRINDEXKEYS_H

#include <index/disktxpos.h>

using AddrId = unsigned long;

constexpr char DB_ADDRINDEX = 'a';

// Type indicators used in DbBaseKey.
constexpr char ADDR_INDEX_SEED_KEY = 'K'; // special key used to find siphash seeds
constexpr char ADDR_INDEX_SPENT_OUTPUT = 'S'; // used to indicate the result is a spent output
constexpr char ADDR_INDEX_CREATED_OUTPUT = 'C'; // used to indicated that the result is a output

// AddrIndexBaseKey is the base class for all leveldb keys used in the AddrIndex.
class AddrIndexBaseKey {
private:

protected:
    char index;
    char key_type;

public:
    AddrIndexBaseKey() : index(), key_type() {}

    AddrIndexBaseKey(const char key_type) : index(DB_ADDRINDEX), key_type(key_type) {
        // Assert that key_type is one of the allowed/defined key types.
        assert((key_type == ADDR_INDEX_SEED_KEY) || (key_type == ADDR_INDEX_SPENT_OUTPUT) || (key_type == ADDR_INDEX_CREATED_OUTPUT));
    }

    bool IsSeedKey() const {
        return key_type == ADDR_INDEX_SEED_KEY;
    }

    bool IsSpentOutput() const {
        return key_type == ADDR_INDEX_SPENT_OUTPUT;
    }

    bool IsCreatedOutput() const {
        return key_type == ADDR_INDEX_CREATED_OUTPUT;
    }

    char GetKeyType() const {
        return key_type;
    }

    char GetIndexType() const {
        return index;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(index);
        READWRITE(key_type);
    }

    friend bool operator==(const AddrIndexBaseKey& a, const AddrIndexBaseKey& b)
    {
        return (a.index == b.index) && (a.key_type == b.key_type);
    }
    
    friend bool operator!=(const AddrIndexBaseKey& a, const AddrIndexBaseKey& b)
    {
        return !(a == b);
    }
};

class AddrIndexSearchKey : public AddrIndexBaseKey {
protected:
    AddrId addr_id;

public:
    AddrIndexSearchKey() : AddrIndexBaseKey() {}

   AddrIndexSearchKey(const char type, const AddrId addr_id): AddrIndexBaseKey(type), addr_id(addr_id) {}

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(AddrIndexBaseKey, *this);
        READWRITE(addr_id);
    }

    AddrId GetAddrId() const {
        return addr_id;
    }
};

class AddrIndexKey : public AddrIndexSearchKey {
protected:

public:
    COutPoint outpoint;
    CDiskTxPos pos;

    AddrIndexKey() : AddrIndexSearchKey() {}

    explicit AddrIndexKey(const char type, const AddrId addr_id, const COutPoint outpoint, const CDiskTxPos pos): AddrIndexSearchKey(type, addr_id), outpoint(outpoint), pos(pos) {}

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(AddrIndexSearchKey , *this);
        READWRITE(outpoint);
        READWRITE(pos);
    };

    bool MatchesSearchKey(const AddrIndexSearchKey& search_key) {
        return (search_key.GetIndexType() == index) && (search_key.GetKeyType() == key_type) && (search_key.GetAddrId() == addr_id);
    }
};


#endif // BITCOIN_INDEX_ADDRINDEX_H
