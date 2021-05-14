import { AssetExportCache } from ".";
import TenableClient from "./TenableClient";
import { AssetExport, ExportAssetsOptions, ExportStatus } from "./types";

import { IntegrationLogger } from "@jupiterone/jupiter-managed-integration-sdk";
import pMap from "p-map";

export async function createAssetExportCache(
  logger: IntegrationLogger,
  client: TenableClient,
): Promise<AssetExportCache> {
  const assetExports = await getAssetExports(client);
  const assetExportMap = new Map<string, AssetExport>();

  logger.info({ assetExports: assetExports.length }, "Fetched asset exports");

  for (const assetExport of assetExports) {
    assetExportMap.set(assetExport.id, assetExport);
  }

  return {
    findAssetExportByUuid: (uuid: string): AssetExport | undefined =>
      assetExportMap.get(uuid),
  };
}

async function getAssetExports(client: TenableClient) {
  const options: ExportAssetsOptions = { chunk_size: 100 };
  const { export_uuid: exportUuid } = await client.exportAssets(options);
  let {
    status,
    chunks_available: chunksAvailable,
  } = await client.fetchAssetsExportStatus(exportUuid);

  while ([ExportStatus.Processing, ExportStatus.Queued].includes(status)) {
    ({
      status,
      chunks_available: chunksAvailable,
    } = await client.fetchAssetsExportStatus(exportUuid));
  }

  const chunkResponses = await pMap(
    chunksAvailable,
    async chunkId => await client.fetchAssetsExportChunk(exportUuid, chunkId),
    { concurrency: 3 },
  );

  const assetExports = chunkResponses.reduce((prev, cur) => {
    return prev.concat(cur);
  }, []);

  return assetExports;
}
