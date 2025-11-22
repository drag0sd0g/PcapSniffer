# PcapSniffer

[![CI Build](https://github.com/drag0sd0g/PcapSniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/drag0sd0g/PcapSniffer/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/drag0sd0g/PcapSniffer/branch/main/graph/badge.svg)](https://codecov.io/gh/drag0sd0g/PcapSniffer)
[![Java Version](https://img.shields.io/badge/Java-21-blue)](https://openjdk.org/projects/jdk/21/)
[![Maven Central](https://img.shields.io/badge/Maven-3.9+-blue)](https://maven.apache.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

クリーンなCLIインターフェースを備えた、モダンで高性能なPCAPファイルアナライザーです。PCAPファイルからネットワークパケット情報を抽出・解析します。

[English README](README.md)

## 特徴

- 🚀 **モダンなJava 21** - 最新のJava機能とパフォーマンス改善を活用
- 📊 **包括的な解析** - Ethernet、IPv4、TCPレベルでの詳細なパケット統計
- 🎯 **クリーンなCLIインターフェース** - picocliを使用した直感的なコマンドライン操作
- 🧪 **高いテストカバレッジ** - JUnit 5による78%の行カバレッジ、72%の分岐カバレッジ
- 📈 **統計レポート** - スループット、パケットレート、プロトコル分布
- 🏗️ **SOLIDアーキテクチャ** - 保守性の高い、よく構造化されたコードベース

## 必要要件

- Java 21以上
- Maven 3.9以上（ソースからビルドする場合）

## インストール

### ソースからビルド

```bash
git clone https://github.com/drag0sd0g/PcapSniffer.git
cd PcapSniffer
mvn clean package
```

これにより、`target/pcapsniffer-2.0.0-jar-with-dependencies.jar`にfat JARが作成されます。

## 使用方法

### 基本的な使い方

```bash
java -jar target/pcapsniffer-2.0.0-jar-with-dependencies.jar <pcapファイル>
```

### コマンドラインオプション

```bash
# ヘルプを表示
java -jar pcapsniffer-2.0.0-jar-with-dependencies.jar --help

# バージョンを表示
java -jar pcapsniffer-2.0.0-jar-with-dependencies.jar --version

# 詳細出力で解析
java -jar pcapsniffer-2.0.0-jar-with-dependencies.jar --verbose example.pcap
```

### 例

```bash
java -jar target/pcapsniffer-2.0.0-jar-with-dependencies.jar 64x8burst.eth2.pcap
```

### 出力

アナライザーは以下について詳細な情報を提供します：
- **Ethernetレベル**: MACアドレス、フレームタイプ
- **IPv4レベル**: 送信元/送信先IP、TTL、チェックサム、フラグ
- **TCPレベル**: ポート、シーケンス番号、フラグ、ウィンドウサイズ
- **統計情報**: 総パケット数、スループット、平均パケットサイズ、ビット毎秒

## アーキテクチャ

PcapSnifferはSOLID原則に従い、関心事の明確な分離を実現しています：

### パッケージ構造

```
com.dragos.pcapsniffer
├── cli/              # コマンドラインインターフェース（picocli）
├── service/          # サービス層
├── analyzer/         # 解析とレポート生成ロジック
├── parser/           # プロトコル固有のパーサー
│   ├── EthernetFrameParser
│   ├── IPv4PacketParser
│   └── TcpPacketParser
└── model/            # データモデルと統計
```

### 主要コンポーネント

- **PcapSnifferCommand**: picocliを使用したCLIエントリーポイント
- **PcapAnalysisService**: バリデーションとオーケストレーションのためのサービス層
- **PcapAnalyzer**: コア解析エンジン
- **Parsers**: プロトコル固有のパケットパーシング
- **PacketStatistics**: 統計情報の集約と計算
- **StatisticsReporter**: 結果のフォーマットと出力

## 開発

### テストの実行

```bash
mvn test
```

### カバレッジレポートの生成

```bash
mvn test jacoco:report
```

カバレッジレポートは `target/site/jacoco/index.html` で確認できます。

### コード品質

プロジェクトは以下を強制します：
- 最低90%の行カバレッジ
- 最低85%の分岐カバレッジ
- SOLID原則に基づくクリーンアーキテクチャ

## 依存関係

### コア依存関係
- **pcap4j 1.8.2** - PCAPファイル処理
- **picocli 4.7.6** - CLIフレームワーク
- **logback 1.5.15** - ロギング
- **slf4j 2.0.16** - ロギングAPI

### テスト依存関係
- **JUnit 5.11.4** - テストフレームワーク
- **Mockito 5.14.2** - モックフレームワーク
- **AssertJ 3.27.1** - Fluent Assertions

すべての依存関係は最新の安定版に更新されています。

## CI/CD

プロジェクトは継続的インテグレーションのためにGitHub Actionsを使用しています：
- プッシュ/PRごとの自動ビルド
- ユニットテストの実行
- Codecovへのコードカバレッジレポート
- アーティファクト生成

## 貢献

貢献を歓迎します！以下の手順でお願いします：
1. リポジトリをフォーク
2. フィーチャーブランチを作成
3. テストを含む変更を作成
4. すべてのテストが通り、カバレッジが維持されていることを確認
5. プルリクエストを送信

## バージョン履歴

### 2.0.0 (2025)
- Java 21にアップグレード
- SOLID原則による完全なリファクタリング
- 包括的なテストスイートの追加（78%カバレッジ）
- picocliによるCLIの実装
- すべての依存関係を最新版に更新
- GitHub ActionsによるCI/CDの追加

### 1.0.0 (2016)
- Java 8による初回リリース
- 基本的なPCAP解析機能

## ライセンス

このプロジェクトはMITライセンスの下でライセンスされています - 詳細はLICENSEファイルをご覧ください。

## 著者

Dragos Dogaru

## 謝辞

- PCAP処理には [pcap4j](https://www.pcap4j.org/) を使用
- CLIは [picocli](https://picocli.info/) を使用
